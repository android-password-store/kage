# 20: Stop identity unwrapping after authenticated success

**What to build:** Decryption avoids scanning and unwrapping with later identities after a candidate file key has been authenticated.

**Blocked by:** #08: Retry identities after scrypt password mismatch.

**Status:** ready-for-agent

- [ ] Authenticate each successfully unwrapped candidate against the header MAC.
- [ ] Stop processing identities immediately after the first authenticated file key.
- [ ] Preserve retry behavior for incorrect identities and fatal behavior for malformed or over-budget stanzas.
- [ ] Test identity ordering and ensure later identities are not invoked after success.
