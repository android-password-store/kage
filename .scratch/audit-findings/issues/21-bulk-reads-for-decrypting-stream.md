# 21: Add bulk reads to decrypting streams

**What to build:** Bulk plaintext reads copy from authenticated chunks efficiently instead of dispatching once per byte.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Implement `read(byte[], off, len)` with standard stream bounds and EOF behavior.
- [ ] Copy from the current authenticated plaintext chunk and load another chunk only when needed.
- [ ] Keep single-byte and bulk reads consistent, including chunk boundaries and final-chunk handling.
- [ ] Test mixed single-byte/bulk reads, partial chunks, EOF, and invalid ranges.
