// A bug two calls deep, where each of the three functions has an `n`. Inside
// `inner` the panel shows inner's own variables, then middle's and top's,
// each under its function: middle's survive the call because middle reads
// them afterwards, and top's parameters keep the values top was called with.
int g;
int h;

void inner(int n) {
  int *p = 0;
  if (h == 1)
    *p = n;
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
