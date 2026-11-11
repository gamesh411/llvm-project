// One statement reached in two calling contexts on one Bug Path: `if (flag)`
// in `take` runs once per call, so its line and its CFG element each hold
// steps from both calls, and only the calling context tells them apart.
static int take(int **pp, int flag) {
  if (flag) {
    *pp = 0;
    return 0;
  }
  return **pp;
}

int several_contexts(int *p, int a, int b) {
  take(&p, a);
  return take(&p, b);
}
