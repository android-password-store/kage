# 22: Add bulk reads to armored input

**What to build:** Armored decryption can consume decoded data in bulk without the inherited per-byte stream fallback.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Implement bulk reads by copying from the current decoded buffer.
- [ ] Decode another armor line only after the current buffer is exhausted.
- [ ] Preserve EOF, line validation, and trailing-data behavior across bulk and single-byte reads.
- [ ] Test mixed reads and boundaries between decoded armor lines.
