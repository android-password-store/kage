# 12: Validate nonce length in in-memory decryption

**What to build:** In-memory decryption reports a defined invalid-nonce error for a truncated payload rather than leaking an array-bounds exception.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Validate payload body length before extracting the nonce.
- [ ] Reuse the established checked nonce extraction behavior where practical.
- [ ] Test truncated in-memory payload bodies and assert the expected exception.
