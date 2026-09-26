# 16: Copy caller-provided X25519 key arrays

**What to build:** Existing X25519 identities and recipients remain stable when callers later mutate or wipe the arrays originally passed to constructors.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Copy externally supplied key material at identity and recipient construction boundaries.
- [ ] Keep cached or derived public-key material consistent with the owned private-key copy.
- [ ] Test that mutating constructor input arrays after construction does not alter identity or recipient behavior.
