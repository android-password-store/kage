# 18: Test AES-128 and AES-192 encrypted SSH imports

**What to build:** Encrypted OpenSSH keys using every advertised AES key size can be imported successfully.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Add externally generated encrypted-key fixtures for AES-128 and AES-192.
- [ ] Exercise both fixtures through the normal encrypted-key import flow.
- [ ] Verify the imported identities can perform a usable cryptographic operation.
