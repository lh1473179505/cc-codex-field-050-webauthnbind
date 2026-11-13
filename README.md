# webauthnbind

A relying-party helper for WebAuthn / FIDO2 ceremonies. `inspect` already parses client data, authenticator data, and the credential store. `verify` is still a stub in this snapshot.

Python 3 plus the `cryptography` package. No Docker, no network, no shelling out to openssl.
