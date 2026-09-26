# 02: Bound untrusted header, stanza, and armor parsing

**What to build:** Decryption rejects oversized unauthenticated input predictably without unbounded memory allocation.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Enforce per-line, per-stanza, and total-header limits while reading, before full-line allocation or decoding.
- [ ] Bound armor-line reads before materializing attacker-controlled lines.
- [ ] Accumulate stanza bodies in a byte-oriented buffer rather than boxed bytes.
- [ ] Cover oversized and unterminated header, stanza, and armor inputs with tests.
