# 03: Validate armored trailing data through EOF

**What to build:** Armored decryption accepts only permitted trailing whitespace and never silently ignores data after the footer.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Continue reading after short reads until actual EOF.
- [ ] Reject any non-whitespace data after the armor footer.
- [ ] Enforce the cumulative trailing-whitespace limit across all reads.
- [ ] Test short-reading streams, excess whitespace, and trailing data after whitespace.
