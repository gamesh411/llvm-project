// Colorful Day demo: see demo/README.md.
int x;

int f(int a, int b) {
  int *p = &x;
  if (a == 0)
    p = 0;
  if (b != 0)
    p = 0;
  return *p;
}
