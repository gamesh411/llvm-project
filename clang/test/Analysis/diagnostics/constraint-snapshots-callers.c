// RUN: rm -rf %t && mkdir %t
// RUN: %clang_analyze_cc1 -analyzer-checker=core \
// RUN:   -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/on.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-summary.py %t/on.plist caller_variables \
// RUN:   | FileCheck %s --check-prefix=CALLERS
// RUN: %python %S/Inputs/constraint-trace-summary.py %t/on.plist variables \
// RUN:   | FileCheck %s --check-prefix=OWN
// RUN: %python %S/Inputs/constraint-trace-delta.py %t/on.plist \
// RUN:   | FileCheck %s --check-prefix=DELTA --implicit-check-not=BAD
// RUN: %python %S/Inputs/constraint-trace-symbols.py %t/on.plist \
// RUN:   | FileCheck %s --check-prefix=SYMBOLS --implicit-check-not=NO-ENTRY \
// RUN:     --implicit-check-not=UNUSED-ENTRY
// RUN: %if z3 %{ %python %S/Inputs/constraint-trace-summary.py %t/on.plist \
// RUN:   smt_caller_variables | FileCheck %s --check-prefix=SMT %}

// With the option off there is no trace, so no caller variables either.
// RUN: %clang_analyze_cc1 -analyzer-checker=core \
// RUN:   -analyzer-output=plist-multi-file -o %t/off.plist -verify %s
// RUN: FileCheck %s --check-prefix=OFF --input-file %t/off.plist
// OFF-NOT: constraint_trace
// OFF-NOT: caller_variables

// The bug is two calls deep, and each of the three frames has an `n`. Inside
// `inner`, the panel's own list holds `inner`'s variables and the caller list
// those of `middle` and `top`, innermost first, each entry with its frame.
// `middle` names `g` too, so `top` leaves it out: it is the same memory.
// `top`'s parameters keep their initial values, and `middle`'s variables stay
// only because they are read after the call.

int g;
int h;

void inner(int n) {
  int *p = 0;
  if (h == 1)
    *p = n; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

void middle(int n, int m) {
  int k = n + 1;
  if (m > 5)
    inner(k);
  g = n + m + k;
}

void top(int n, int m) {
  if (n == 2 && g == 4)
    middle(n * 3, m);
}

// The top frame has no caller.
// CALLERS:      EVENT "Assuming 'n' is equal to 2": {{$}}
// CALLERS-NEXT: EVENT "Assuming 'g' is equal to 4": {{$}}
// CALLERS-NEXT: EVENT "Calling 'middle'": {{$}}
// The event that enters a call shows the caller's own snapshot.
// CALLERS-NEXT: EVENT "Entered call from 'top'": {{$}}
// CALLERS-NEXT: EVENT "Assuming 'm' is > 5": top#0: m = reg_$[[M:[0-9]+]]<int m> [symbol]; top#0: n = reg_$[[N:[0-9]+]]<int n> [symbol]{{$}}
// CALLERS-NEXT: EVENT "Calling 'inner'": top#0: m = reg_$[[M]]<int m> [symbol]; top#0: n = reg_$[[N]]<int n> [symbol]{{$}}
// CALLERS-NEXT: EVENT "Entered call from 'middle'": top#0: m = reg_$[[M]]<int m> [symbol]; top#0: n = reg_$[[N]]<int n> [symbol]{{$}}
// CALLERS-NEXT: EVENT "'p' initialized to a null pointer value": middle#1: g = reg_$[[G:[0-9]+]]<int g> [symbol]; middle#1: k = 7 [integer]; middle#1: m = reg_$[[M]]<int m> [symbol]; middle#1: n = 6 [integer]; top#0: m = reg_$[[M]]<int m> [symbol]; top#0: n = reg_$[[N]]<int n> [symbol]{{$}}
// CALLERS-NEXT: EVENT "Assuming 'h' is equal to 1": middle#1: g = reg_$[[G]]<int g> [symbol]; middle#1: k = 7 [integer]; middle#1: m = reg_$[[M]]<int m> [symbol]; middle#1: n = 6 [integer]; top#0: m = reg_$[[M]]<int m> [symbol]; top#0: n = reg_$[[N]]<int n> [symbol]{{$}}
// CALLERS-NEXT: EVENT "Dereference of null pointer (loaded from variable 'p')": middle#1: g = reg_$[[G]]<int g> [symbol]; middle#1: k = 7 [integer]; middle#1: m = reg_$[[M]]<int m> [symbol]; middle#1: n = 6 [integer]; top#0: m = reg_$[[M]]<int m> [symbol]; top#0: n = reg_$[[N]]<int n> [symbol]{{$}}

// The own list keeps its meaning: the variables of the step's frame only.
// OWN:      EVENT "Assuming 'm' is > 5": g = reg_$[[#]]<int g> [symbol]; k = 7 [integer]; m = reg_$[[#]]<int m> [symbol]; n = 6 [integer]{{$}}
// OWN:      EVENT "'p' initialized to a null pointer value": h = reg_$[[#]]<int h> [symbol]; n = 7 [integer]; p = 0 [integer]{{$}}
// OWN-NEXT: EVENT "Assuming 'h' is equal to 1": h = reg_$[[#]]<int h> [symbol]; n = 7 [integer]; p = 0 [integer]{{$}}
// OWN-NEXT: EVENT "Dereference of null pointer (loaded from variable 'p')": h = reg_$[[#]]<int h> [symbol]{{$}}

// Caller lists are deltas: entering a call inserts the frame that made it,
// and nothing changes them while the callee runs.
// DELTA:     STRINGS
// DELTA-NOT: callers
// DELTA:     callers +2 ~0 -0{{$}}
// DELTA-NOT: callers
// DELTA:     callers +4 ~0 -0{{$}}
// DELTA-NOT: callers

// Every symbol a caller's variable holds has an entry in the table.
// SYMBOLS: SYMBOL reg_$[[#]]<int m> region_value name m{{$}}

// A caller's variable has its SMT-LIB term, as the frame's own variables do.
// SMT: EVENT "Dereference of null pointer (loaded from variable 'p')": middle#1: g = reg_$[[#]] [signed]; middle#1: m = reg_$[[#]] [signed]; top#0: m = reg_$[[#]] [signed]; top#0: n = reg_$[[#]] [signed]{{$}}
