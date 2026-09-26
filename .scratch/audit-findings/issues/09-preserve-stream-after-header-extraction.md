# 09: Preserve the stream remainder after header extraction

**What to build:** Callers extracting an age header can continue reading the payload from the same input without losing bytes to parser read-ahead.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Ensure extraction does not discard or hide bytes read beyond the header, for binary and armored input.
- [ ] Either avoid read-ahead past the header or expose the buffered remainder in the API result.
- [ ] Document the stream ownership and continuation contract.
- [ ] Test extraction followed by reading the complete payload from a stream.
