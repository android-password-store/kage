# 08: Retry identities after scrypt password mismatch

**What to build:** Decryption can continue to a later valid identity when an earlier scrypt identity has the wrong password.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Translate only AEAD authentication failure into an incorrect-identity result.
- [ ] Allow the identity resolver to try subsequent identities after that result.
- [ ] Keep malformed stanzas and excessive work-factor failures fatal.
- [ ] Test wrong-password then correct-password identity ordering.
