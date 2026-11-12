// `hits` never exceeds `n`, but the analyzer stops following the loop after a
// few passes and forgets what the loop did, so the path assumes it does.
// Analyze with `-analyzer-config widen-loops=true`.
int count(const int *items, unsigned n) {
  unsigned hits = 0;
  for (unsigned i = 0; i < n; ++i)
    if (items[i])
      ++hits;
  int *p = 0;
  if (hits > n)
    return *p;
  return 0;
}
