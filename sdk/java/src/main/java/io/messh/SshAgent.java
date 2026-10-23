package io.messh;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/** A key held by ssh-agent. Protocol (draft-miller-ssh-agent): uint32 length, message type, payload. */
final class SshAgent implements Signer {
  private static final byte REQUEST_IDENTITIES = 11, IDENTITIES_ANSWER = 12, SIGN_REQUEST = 13, SIGN_RESPONSE = 14;
  private static final String PIPE = "\\\\.\\pipe\\openssh-ssh-agent";

  private final String path;
  private final byte[] blob;
  private final byte[] pub;

  private SshAgent(String path, byte[] blob, byte[] pub) {
    this.path = path;
    this.blob = blob;
    this.pub = pub;
  }

  private record Key(byte[] blob, byte[] pub, String fingerprint) {}

  static Signer load(String fingerprint, Path socket) {
    String path = socket != null ? socket.toString() : System.getenv("SSH_AUTH_SOCK");
    if ((path == null || path.isEmpty()) && System.getProperty("os.name", "").startsWith("Windows")) path = PIPE;
    if (path == null || path.isEmpty()) {
      throw new MesshException("invalid_key", "ssh-agent isn't running (SSH_AUTH_SOCK is not set); start it: eval \"$(ssh-agent)\" && ssh-add");
    }
    List<Key> keys = new ArrayList<>();
    try {
      byte[] reply = call(path, new byte[] {REQUEST_IDENTITIES});
      if (reply.length == 0 || reply[0] != IDENTITIES_ANSWER) throw new IOException("it wouldn't list its keys");
      ByteBuffer r = ByteBuffer.wrap(reply, 1, reply.length - 1);
      for (int n = r.getInt(); n > 0; n--) {
        byte[] blob = str(r);
        str(r); // comment
        ByteBuffer b = ByteBuffer.wrap(blob);
        if (!"ssh-ed25519".equals(new String(str(b), StandardCharsets.US_ASCII))) continue;
        byte[] pub = str(b);
        if (pub.length == 32) keys.add(new Key(blob, pub, Wba.fingerprint(pub)));
      }
    } catch (IOException e) {
      throw new MesshException("invalid_key", "ssh-agent at " + path + ": " + e.getMessage());
    } catch (BufferUnderflowException e) {
      throw new MesshException("invalid_key", "ssh-agent at " + path + ": malformed reply");
    }
    String listed = keys.stream().map(Key::fingerprint).collect(Collectors.joining(", "));
    if (keys.isEmpty()) throw new MesshException("invalid_key", "ssh-agent has no Ed25519 keys; add yours with ssh-add ~/.ssh/id_ed25519");
    List<Key> pick = fingerprint == null ? keys : keys.stream().filter(k -> k.fingerprint().equals(fingerprint)).toList();
    if (pick.isEmpty()) throw new MesshException("invalid_key", "ssh-agent has no key " + fingerprint + "; it has " + listed);
    if (pick.size() > 1) {
      throw new MesshException("invalid_key", "ssh-agent has " + keys.size() + " Ed25519 keys; choose one with KeySource.sshAgent(fingerprint): " + listed);
    }
    return new SshAgent(path, pick.get(0).blob(), pick.get(0).pub());
  }

  @Override
  public byte[] publicKey() {
    return pub.clone();
  }

  @Override
  public byte[] sign(byte[] message) {
    byte[] b = Wba.sshString(blob), m = Wba.sshString(message);
    byte[] msg = ByteBuffer.allocate(1 + b.length + m.length + 4).put(SIGN_REQUEST).put(b).put(m).putInt(0).array();
    try {
      byte[] reply = call(path, msg);
      if (reply.length == 0 || reply[0] != SIGN_RESPONSE) {
        throw new MesshException("sign_failed", "ssh-agent refused to sign; is the key still loaded (ssh-add -l)?");
      }
      ByteBuffer sig = ByteBuffer.wrap(str(ByteBuffer.wrap(reply, 1, reply.length - 1)));
      byte[] type = str(sig), raw = str(sig);
      if (!"ssh-ed25519".equals(new String(type, StandardCharsets.US_ASCII)) || raw.length != 64) throw new BufferUnderflowException();
      return raw;
    } catch (IOException e) {
      throw new MesshException("sign_failed", "ssh-agent: " + e.getMessage());
    } catch (BufferUnderflowException e) {
      throw new MesshException("sign_failed", "ssh-agent returned an unexpected signature");
    }
  }

  @Override
  public String toString() {
    return "messh.Signer(ssh-agent)";
  }

  private static byte[] str(ByteBuffer r) {
    int n = r.getInt();
    if (n < 0 || n > r.remaining()) throw new BufferUnderflowException();
    byte[] s = new byte[n];
    r.get(s);
    return s;
  }

  private static byte[] call(String path, byte[] msg) throws IOException {
    if (path.startsWith("\\\\.\\pipe\\")) {
      try (RandomAccessFile pipe = new RandomAccessFile(path, "rw")) {
        pipe.write(Wba.sshString(msg));
        byte[] reply = new byte[checked(pipe.readInt())];
        pipe.readFully(reply);
        return reply;
      }
    }
    try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX); Selector sel = Selector.open()) {
      ch.connect(UnixDomainSocketAddress.of(path));
      ByteBuffer out = ByteBuffer.wrap(Wba.sshString(msg));
      while (out.hasRemaining()) ch.write(out);
      ch.configureBlocking(false);
      ch.register(sel, SelectionKey.OP_READ);
      ByteBuffer len = read(ch, sel, ByteBuffer.allocate(4));
      return read(ch, sel, ByteBuffer.allocate(checked(len.getInt()))).array();
    }
  }

  private static int checked(int n) throws IOException {
    if (n < 0 || n > 1 << 20) throw new IOException("reply too large");
    return n;
  }

  /** Fills b, waiting at most 30 s for each read (a hardware key may wait for a touch). */
  private static ByteBuffer read(SocketChannel ch, Selector sel, ByteBuffer b) throws IOException {
    while (b.hasRemaining()) {
      if (sel.select(30_000) == 0) throw new IOException("ssh-agent timed out");
      sel.selectedKeys().clear();
      if (ch.read(b) < 0) throw new IOException("ssh-agent closed the connection");
    }
    return b.flip();
  }
}
