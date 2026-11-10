// `g` is checked non-null, then `refresh`, whose body the analyzer cannot see,
// may replace it, and the path assumes the new value null.
int *g;
void refresh(void);

int f(void) {
  if (!g)
    return 0;
  int before = *g;
  refresh();
  if (g)
    return before;
  return before + *g;
}
