# messh for Python

Sign and verify HTTP requests as a [messh](https://messh.io) identity with **Web Bot Auth**: RFC 9421 HTTP Message Signatures, Ed25519, `tag="web-bot-auth"`.

```sh
pip install messh-sdk            # import name: messh
pip install "messh-sdk[httpx]"   # optional httpx auth
```

## Sign (agent)

```python
from messh import Client, key_file

client = Client("mukul", key=key_file("~/.ssh/id_ed25519"))
client.post("https://api.example.com/deploy", json={"env": "staging"})
```

Use the ssh-ed25519 key you published with `messh publish`. The private key never leaves your machine.

## Agents and CI

Configure it with environment variables instead of code: `MESSH_IDENTITY`, `MESSH_KEY` (PEM, or base64 of PEM or PKCS#8 DER) or `MESSH_KEY_FILE`, and `MESSH_REGISTRY`. `whoami` checks the key is published, so a missing `messh publish` fails at startup with `not_published` instead of every API answering 401.

```python
client = Client.from_env()
me = client.whoami()  # PublishedKey(identity, key_name, key_id, fingerprint, agent_url)
```

Passphrase-protected key? Load it into ssh-agent (`ssh-add`) and pass `key=ssh_agent()`.

## Verify (API)

```python
from fastapi import Depends, FastAPI
from messh.verify import Agent, MesshAuthMiddleware, current_agent

app = FastAPI()
app.add_middleware(MesshAuthMiddleware, trust=["mukul"], paths=["/api/"])

@app.post("/api/deploy")
def deploy(agent: Agent = Depends(current_agent)):
    return {"hello": agent.identity}
```

Without a framework: `Verifier(trust=["mukul"]).verify(method, url, headers, body)`.

Full reference (every function, input and error code): https://github.com/messhio/messh/blob/main/sdk/README.md

License: Apache-2.0
