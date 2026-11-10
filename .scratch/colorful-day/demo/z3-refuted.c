// The range-based solver keeps x * x == -1 as a constraint on an opaque
// product, so it reports the dereference. No 32-bit square is -1, so Z3 finds
// this Bug Path infeasible.
int square_is_minus_one(int x) {
  int *p = 0;
  if (x * x == -1)
    return *p;
  return 0;
}
