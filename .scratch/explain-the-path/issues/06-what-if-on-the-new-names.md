# 06: What-If on the new names

**What to build:** A report reader writes a What-If Constraint on a caller's variable or on an access path such as `gl->cellsize` or `this->Current`, and gets a Path Verdict as for a local variable.
This ticket closes slice 2 of `../spec.md`.

**Blocked by:** 04, 05

**Status:** ready-for-agent

- [ ] The left side of a comparison accepts access paths made of identifiers, `.`, `->`, `*` and constant subscripts, matched as text against display names, not parsed as C.
- [ ] A name resolves to any variable of any frame or any symbol display name visible at the anchor Path Step that has an SMT-LIB term.
- [ ] A name that resolves to more than one symbol gives an Unknown verdict that names the candidates.
- [ ] The suggestion list offers every constrainable name at the selected Path Step, and choosing a frame-qualified entry resolves an ambiguous name.
- [ ] "Holds throughout the path" works on access paths.
- [ ] Functional tests cover a caller's variable, an access path, an ambiguous name and a trace without the new keys.
- [ ] Slice acceptance in a browser at 1400 and 900 pixels on the two demos and three LLVM reports from the triage study.
- [ ] Table A4 of `../../colorful-day/research/triage-study.md` is measured again with the study's own scripts on a fresh LLVM run, and the result is recorded in Comments.
- [ ] Plist size and analysis time on that run are reported.
- [ ] The CodeChecker documentation page describes the new names and the ambiguity verdict.
