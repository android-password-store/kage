# 15: Avoid duplicate X25519 scalar multiplication

**What to build:** X25519 wrap and unwrap compute the shared secret once per agreement.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Return the validated shared secret already populated by the agreement operation.
- [ ] Preserve existing low-order-point and output validation behavior.
- [ ] Verify wrap/unwrap behavior remains unchanged.
