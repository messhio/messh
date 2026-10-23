package io.messh.verify;

import java.time.Duration;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Replay store. {@code add} returns false if key was seen within ttl. Use a shared store for several instances. */
public interface NonceStore {
  boolean add(String key, Duration ttl);

  /** In-process store. */
  static NonceStore memory() {
    Map<String, Long> seen = new ConcurrentHashMap<>();
    return (key, ttl) -> {
      long now = System.nanoTime();
      for (Iterator<Map.Entry<String, Long>> it = seen.entrySet().iterator(); it.hasNext(); ) {
        if (it.next().getValue() - now < 0) it.remove();
      }
      return seen.putIfAbsent(key, now + ttl.toNanos()) == null;
    };
  }
}
