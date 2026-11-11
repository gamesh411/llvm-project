#!/usr/bin/env python3
"""Print a C function whose null dereference is reached after N parameter
checks, for a Bug Path long enough that the exploded graph reclaims nodes on
the way. Usage: constraint-trace-long-path.py N"""

import sys

n = int(sys.argv[1])
print("int f(int *p, %s) {" % ", ".join("int a%d" % i for i in range(n)))
print("  if (p) return 0;")
for i in range(n):
    print("  if (a%d != %d) return %d;" % (i, i + 1, i + 1))
print("  return *p;")
print("}")
