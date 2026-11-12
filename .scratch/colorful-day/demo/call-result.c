// `read_len`'s body is out of the analyzer's sight, so the length is the
// result of that call, made inside `next_len`. A checker models `malloc`, and
// the analyzer records no reason for the pointer it returns.
void *malloc(unsigned long);
void free(void *);
int read_len(void);

static int next_len(void) { return read_len(); }

int copy(int *out) {
  char *buf = malloc(16);
  if (!buf)
    return -1;
  int len = next_len();
  if (len > 16)
    out = 0;
  free(buf);
  return *out;
}
