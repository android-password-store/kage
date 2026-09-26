# 05: Limit scrypt resources before derivation

**What to build:** Decrypting an untrusted scrypt stanza cannot trigger excessive work or memory allocation before authentication.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Apply a conservative default work/memory budget before invoking scrypt derivation.
- [ ] Reject a stanza that exceeds the configured budget before expensive allocation begins.
- [ ] Preserve fatal errors for malformed stanzas and over-budget parameters.
- [ ] Make support for larger budgets an explicit opt-in, if provided.
- [ ] Test boundary parameters and verify over-budget input is rejected before derivation.
