# 04: Access-path names

**What to build:** A symbol that stands for the initial value of a field, element or pointee shows as the expression a reader would write, such as `Builder.InsertPt.Block`, `*p`, `p->len` or `this->Current`, in the Constraint Snapshot and in the accumulated path condition.

**Blocked by:** 01

**Status:** resolved

- [x] A region value symbol's entry in the symbol table has a display name taken from the analyzer's own descriptive naming of memory regions.
- [x] A region the analyzer cannot describe gets no name, and the UI falls back to the origin label or the raw dump.
- [x] Lit covers a field, a nested field, an element with a constant index, a pointee, a field behind a pointer parameter, and `this->field`.
- [x] "Other symbols" and the accumulated path condition show the name, with the raw symbol on hover.
- [x] The line picker still tells visits of a line apart after naming.
- [x] Names are labels: two symbols with the same name stay two rows.
- [x] Verified in a browser on the tmux demo report and on an LLVM report from the triage study whose deciding constraint was unnamed (cases 18 or 25).

## Comments

2026-11-12, ticket 04 worker.

Commits: `llvm-project@62bbbbf2c391..87ce0000f1a9` (Clang `62bbbbf2c391` and `fe10c4a08577`, docs `95bf1c842d8c`, trace format doc, demo and dev loop `c84117199dff` and `87ce0000f1a9`); `codechecker@89d2c578a..35d23b2e2`.

### Rule verified

Names come only from the analyzer's region, never from a dump: verified at `llvm-project@f99fcf1830e4`, `MemRegion::getDescriptiveName` returns nothing for any `SymbolicRegion` and `CXXThisRegion`, and a field read through a pointer is almost never `Field{SymRegion{p}}` but `Field{Element{SymRegion{reg_$<T * p>},0 S64b,T}}`, since the store first views the pointee as an element of its type.
So `describeRegion` in `BugReporter.cpp` now walks the region itself: variables, fields, `this`, array elements with a constant index or an index whose value is named memory, and the pointee of a pointer whose value is the initial or replaced value of named memory (`*p`, `p[2]`, `p->len`, `this->Current`).
An element view whose type differs from the pointer's pointee names the pointer through a cast (`((Inner *)data)->len`); an element of anything that is not an array of that element type gets no name; base classes and anonymous structs and unions are left out.
The pointee of a conjured value (a call's result), a temporary and a computed index stay unnamed.
Region value names, the `region` of derived entries and the memory an invalidation replaced all use it, which was the lead's addition 1.
The UI's `regionValueName`, which read the last word of a `reg_$` dump, is gone (addition 4); an atom without an entry name or a variable now leaves its expression raw.

### Decisions

- A `region_value` entry gets `name`; `derived` keeps `region`, which is now wider. Separate keys rather than one, because a derived symbol's access path is part of a label that names the replacing call, while a region value's name is the whole label.
- Expression types (addition 3): done. They are clean and additive: a new trace key `expressions`, one `{symbol, type, pointer}` per symbolic expression that the path condition constrains or a variable holds (not their subexpressions), sorted by dump. Kept out of `symbols`, since the spec says expressions have no entry there and the readers key labels on "has an entry"; the JS `typeOf(dump)` reads either table. `LK` style ranges now read "not 0".
- Extents get `region`, the memory whose size they are, read "size of `*gd->linedata`". Not asked for, but it was the last raw atom in the tmux accumulated condition and needed one line in Clang.
- A region value in an expression goes by the variable that held it first, as its own path condition row does, and by its name otherwise. Under a variable, a label that only repeats the variable's name (a parameter's own value) shows the dump instead, in Known here and in the accumulated condition.
- A label's tooltip now starts with the whole label, because the two-line clamp under a variable cut `Op.Node->ValueList[Op.ResNo].V.SimpleTy` at 900 px with no way to read it.
- `dev-loop.sh fixture` gains `access_path` (`demo/access-path.c`), and its `no_smtlib` re-encoding carries `expressions` (a key of string indices, the ticket 01 trap).

### Verification

- Emission off: 21 of 21 small inputs and 146 of 146 tmux TUs byte-identical to the pre-change binary (two runs each, apart from the revision string); emission on: all equal after dropping `symbols` and `expressions` and their trailing strings (`/Users/efulop/colorful-day-env/t04/`, `small.txt`, `tmux.txt`).
- tmux plists with `crosscheck-with-z3`: off 1,350,221 both; on 5,388,483 at ticket 03's head and 5,422,895 now (+34,412, +0.64%). 275 of 298 region values have a name; derived entries with a region went from 201 to 237 of 255, invalidations naming their memory from 88 to 103 of 112; 75 expressions, all typed.
- Checks: Colorful Day lit (`diagnostics/` filtered on `constraint`) 9 passed, 1 unsupported, including the new `constraint-snapshots-names.cpp`; `clang/test/Analysis` 1271 discovered, 1 failed (the user's untracked `bstring-UninitRead-partial-init.c`), `clang-extdef-mapping` rebuilt with Clang; functest 40 passed; report-converter unit 157; server unit 119; jest 92 (5 suites); eslint clean; pycodestyle clean, pylint 10.00, mypy clean; clang-format clean on the diff.
- Browser, `/Users/efulop/colorful-day-env/screens/`, 1400 and 900 px, no panel element overflows at either width:
  - `t04-access-path-1400/900.png`, `t04-access-path-accumulated-900.png` (demo report 152): `grid->rows` at least 3, `line->cells[0].width` 1, `line->next` non-null, `line->next->cells[1].flags & 4` `[1, 4]`.
  - `t04-tmux-1400/900.png`, `t04-tmux-accumulated-1400/900.png` (grid.c:1073, report 221): every row of the accumulated condition renders from labels, such as `xx >= gd->linedata[py].cellsize` not 0, `py >= (gd->hsize + gd->sy)` 0, `(py * 40) < size of *gd->linedata` not 0, `flags & 1` 1.
  - `t04-llvm-case1-1400/900.png` (study case 1, report 233, Step 3): "`this->Current` after `this->parse(prec::LogicalOr)` may have changed it, line 3486" non-null, beside `this->Current` null, its value before the call.
  - `t04-llvm-case25-1400/900.png` (study case 25, report 244, Step 3 at line 22004): `VT` is 0 and reads `Op.Node->ValueList[Op.ResNo].V.SimpleTy`, so the deciding constraint is named: the simple type of the operation's result is assumed to be `INVALID_SIMPLE_VALUE_TYPE`.
  - `t04-llvm-case18-1400/900.png` (study case 18, report 237, Step 12): not answered. The deciding `[0, 0]` is the `Block` of a temporary `VPInsertPoint` replaced by the opaque `ilist_iterator` constructor, and reads "a value after `*this` may have changed it, ilist_node.h:123"; a temporary has no access path.
  - `t04-picker-1400.png`: the line picker on `several-contexts.c` line 5 still tells the visits apart (`flag = not 0`, `flag = 0`).
- Names are labels: rows stay keyed by dump (`SnapshotRows` jest tests); `two symbols with one label stay two rows` covers a shared name too.

### Open points

- Pointees of call results stay raw, such as `reg_$12<pointer Element{SymRegion{reg_$10<pointer Element{SymRegion{conj_$8{...}}...` in case 18. Clang could write the base symbol and the path after it, so a reader builds "`LoopRegion`->CanIVInfo..." from the call's label; that needs a structured name, not text.
- Temporaries have no name, which leaves case 18's deciding constraint as "a value after `*this` may have changed it"; naming a temporary by the expression that made it would mislead here, since the temporary came from an implicit conversion of `OriginalTerminator`.
- Metadata symbols (string lengths) have no name.
- The invalidation statement of a constructor prints as its argument (`*this`), which reads oddly in case 18.
