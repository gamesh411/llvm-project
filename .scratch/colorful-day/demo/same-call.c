// The analyzer makes a new value for each call to an opaque function and does
// not assume two calls agree, so it takes both branches below although a real
// get() would return the same number twice.
int get(void);

void same_call(void) {
  int *p = 0;
  if (get() > 0 && get() <= 0)
    *p = 1;
}
