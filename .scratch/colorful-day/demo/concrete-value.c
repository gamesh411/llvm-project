// `p` holds the concrete address &x until it takes the null `q` assumes.
int x;

int f(int *q) {
  int *p = &x;
  if (!q)
    p = q;
  return *p;
}
