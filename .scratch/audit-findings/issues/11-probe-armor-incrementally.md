# 11: Probe armor incrementally

**What to build:** Header extraction on a live stream does not wait for a fixed-size probe after the input format is already identifiable.

**Blocked by:** #10: Detect armor from its opening marker.

**Status:** ready-for-agent

- [ ] Read only enough bytes to distinguish binary input from a complete armor prefix.
- [ ] Do not require a fixed 1 KiB-plus read or EOF before parsing a short complete header.
- [ ] Test with a live/short-reading stream that supplies a complete header and then remains open.
