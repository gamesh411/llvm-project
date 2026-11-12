# 04: Access-path names

**What to build:** A symbol that stands for the initial value of a field, element or pointee shows as the expression a reader would write, such as `Builder.InsertPt.Block`, `*p`, `p->len` or `this->Current`, in the Constraint Snapshot and in the accumulated path condition.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] A region value symbol's entry in the symbol table has a display name taken from the analyzer's own descriptive naming of memory regions.
- [ ] A region the analyzer cannot describe gets no name, and the UI falls back to the origin label or the raw dump.
- [ ] Lit covers a field, a nested field, an element with a constant index, a pointee, a field behind a pointer parameter, and `this->field`.
- [ ] "Other symbols" and the accumulated path condition show the name, with the raw symbol on hover.
- [ ] The line picker still tells visits of a line apart after naming.
- [ ] Names are labels: two symbols with the same name stay two rows.
- [ ] Verified in a browser on the tmux demo report and on an LLVM report from the triage study whose deciding constraint was unnamed (cases 18 or 25).
