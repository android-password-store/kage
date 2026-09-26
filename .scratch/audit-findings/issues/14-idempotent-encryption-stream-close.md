# 14: Make encryption stream close safe to repeat

**What to build:** Closing encryption and armor output streams multiple times produces one valid ciphertext and footer, while writes after close fail predictably.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Make repeated close calls on both output wrappers no-ops after the first close.
- [ ] Ensure final chunks and armor footers are emitted at most once.
- [ ] Reject writes after close with a defined stream error.
- [ ] Test repeated close for empty and non-empty streams, including wrapped armor output.
