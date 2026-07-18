"""Loads the PHI data-encryption key (DEK) at startup.

Two providers:
- ``env``   — the Fernet key is read directly from PHI_ENCRYPTION_KEY.
- ``vault`` — envelope encryption: the DEK is stored *wrapped* (transit
  ciphertext) in config; at boot the app authenticates to Vault via AppRole and
  asks the transit engine to unwrap it. The unwrapping key (KEK) never leaves
  Vault; the plaintext DEK exists only in this process's memory.

Fails closed: any error unwrapping the key raises, so the app will not start
serving PHI with a bad or missing key.
"""
import base64
import json
import ssl
import urllib.request

from .config import settings


class KeyProviderError(RuntimeError):
    pass


def _vault_post(path: str, body: dict, token: str | None = None) -> dict:
    url = f"{settings.vault_addr.rstrip('/')}/v1/{path}"
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("X-Vault-Token", token)
    ctx = ssl.create_default_context(cafile=settings.vault_cacert) if settings.vault_cacert \
        else ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        return json.loads(resp.read().decode())


def _load_from_vault() -> bytes:
    # 1. AppRole login → client token.
    login = _vault_post(
        "auth/approle/login",
        {"role_id": settings.vault_role_id, "secret_id": settings.vault_secret_id},
    )
    token = login["auth"]["client_token"]

    # 2. Ask transit to decrypt (unwrap) the wrapped DEK.
    decrypted = _vault_post(
        f"transit/decrypt/{settings.vault_transit_key}",
        {"ciphertext": settings.wrapped_phi_dek},
        token=token,
    )
    # transit returns the original plaintext base64-encoded; it was itself the
    # base64 Fernet key, so one more decode yields the raw Fernet key bytes.
    plaintext_b64 = decrypted["data"]["plaintext"]
    return base64.b64decode(plaintext_b64)


def load_phi_key() -> bytes:
    """Return the Fernet key bytes for PHI encryption."""
    try:
        if settings.key_provider == "vault":
            return _load_from_vault()
        return settings.phi_encryption_key.encode()
    except Exception as e:  # fail closed
        raise KeyProviderError(f"Could not load PHI encryption key ({settings.key_provider}): {e}") from e
