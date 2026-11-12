# 02: Replaced values get a label

**What to build:** A report reader sees why the analyzer invented a value: because a call might have changed it, with the call named, or because the analyzer stopped tracking a loop.
A field of an object replaced that way reads as its access path plus the call, such as "`Tok.Kind` after `Lex(Tok)` may have changed it, line 57".

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] Clang writes the reasons "invalidation by a call" and "loop widening" when it knows them from what the analyzer recorded, never from statement text.
- [ ] A derived symbol's entry names its parent symbol and the access path of its region.
- [ ] Lit covers a value invalidated by an opaque call, a loop-widened value, and a derived field of an invalidated object.
- [ ] The panel labels all three, with the invalidating call or loop linked to its nearest Path Step and the raw symbol on hover.
- [ ] Reader unit and jest tests cover the new reasons and derived entries.
- [ ] Verified in a browser on a demo fixture for each reason and on one LLVM report from `../../colorful-day/research/triage-study.md` whose case turned on an invalidated value (cases 1, 4 or 22).
