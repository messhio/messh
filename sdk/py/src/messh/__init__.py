"""messh: sign and verify HTTP requests as a messh identity (Web Bot Auth).

Client side::

    from messh import Client, key_file
    client = Client("mukul", key=key_file("~/.ssh/id_ed25519"))
    client.get("https://api.example.com/hello")

Server side::

    from messh.verify import Verifier, MesshAuthMiddleware
"""

from .client import DEFAULT_REGISTRY, Client, PublishedKey, Response, __version__
from .errors import MesshError, VerifyError
from .keys import Signer, key_env, key_file, key_seed, ssh_agent

__all__ = ["Client", "PublishedKey", "Response", "MesshError", "VerifyError", "Signer", "key_file", "key_env", "key_seed",
           "ssh_agent", "DEFAULT_REGISTRY", "MesshAuth", "__version__"]


def __getattr__(name):
    if name == "MesshAuth":  # httpx.Auth; needs `pip install messh[httpx]`
        from .client import _httpx_auth
        return _httpx_auth()
    raise AttributeError(name)
