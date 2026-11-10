// One null dereference reachable through two independent null assignments.
// The analyzer reports it once, along the Bug Path a == 0, b != 0.
int x;

int f(int a, int b) {
  int *p = 0;
  if (a != 0)
    p = &x;
  if (b == 0)
    p = &x;
  if (a == 0)
    p = 0;
  if (b != 0)
    p = 0;
  return *p;
}
