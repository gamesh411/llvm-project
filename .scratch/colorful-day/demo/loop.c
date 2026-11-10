// A null dereference after a loop, with several iterations of the same lines
// on one Bug Path, for trying the Path Step picker.
int total;

int f(int *p, int n) {
  for (int i = 0; i < 3; ++i) {
    if (i == 2)
      p = 0;
    total = total + n;
  }
  return *p + total;
}
