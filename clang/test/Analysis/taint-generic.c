// RUN: %clang_analyze_cc1 -Wno-format-security -Wno-pointer-to-int-cast \
// RUN:   -Wno-incompatible-library-redeclaration -verify %s \
// RUN:   -analyzer-checker=alpha.security.taint \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=alpha.security.ArrayBoundV2 \
// RUN:   -analyzer-config \
// RUN:     alpha.security.taint.TaintPropagation:Config=%S/Inputs/taint-generic-config.yaml

// RUN: %clang_analyze_cc1 -Wno-format-security -Wno-pointer-to-int-cast \
// RUN:   -Wno-incompatible-library-redeclaration -verify %s \
// RUN:   -DFILE_IS_STRUCT \
// RUN:   -analyzer-checker=alpha.security.taint \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=alpha.security.ArrayBoundV2 \
// RUN:   -analyzer-config \
// RUN:     alpha.security.taint.TaintPropagation:Config=%S/Inputs/taint-generic-config.yaml

// RUN: not %clang_analyze_cc1 -Wno-pointer-to-int-cast \
// RUN:   -Wno-incompatible-library-redeclaration -verify %s \
// RUN:   -analyzer-checker=alpha.security.taint \
// RUN:   -analyzer-config \
// RUN:     alpha.security.taint.TaintPropagation:Config=justguessit \
// RUN:   2>&1 | FileCheck %s -check-prefix=CHECK-INVALID-FILE

// CHECK-INVALID-FILE: (frontend): invalid input for checker option
// CHECK-INVALID-FILE-SAME:        'alpha.security.taint.TaintPropagation:Config',
// CHECK-INVALID-FILE-SAME:        that expects a valid filename instead of
// CHECK-INVALID-FILE-SAME:        'justguessit'

// RUN: not %clang_analyze_cc1 -Wno-incompatible-library-redeclaration \
// RUN:   -verify %s \
// RUN:   -analyzer-checker=alpha.security.taint \
// RUN:   -analyzer-config \
// RUN:     alpha.security.taint.TaintPropagation:Config=%S/Inputs/taint-generic-config-ill-formed.yaml \
// RUN:   2>&1 | FileCheck -DMSG=%errc_EINVAL %s -check-prefix=CHECK-ILL-FORMED

// CHECK-ILL-FORMED: (frontend): invalid input for checker option
// CHECK-ILL-FORMED-SAME:        'alpha.security.taint.TaintPropagation:Config',
// CHECK-ILL-FORMED-SAME:        that expects a valid yaml file: [[MSG]]

// RUN: not %clang_analyze_cc1 -Wno-incompatible-library-redeclaration \
// RUN:   -verify %s \
// RUN:   -analyzer-checker=alpha.security.taint \
// RUN:   -analyzer-config \
// RUN:     alpha.security.taint.TaintPropagation:Config=%S/Inputs/taint-generic-config-invalid-arg.yaml \
// RUN:   2>&1 | FileCheck %s -check-prefix=CHECK-INVALID-ARG

// CHECK-INVALID-ARG: (frontend): invalid input for checker option
// CHECK-INVALID-ARG-SAME:        'alpha.security.taint.TaintPropagation:Config',
// CHECK-INVALID-ARG-SAME:        that expects an argument number for propagation
// CHECK-INVALID-ARG-SAME:        rules greater or equal to -1

extern int some_global_flag_to_branch_on;

int scanf(const char *restrict format, ...);
char *gets(char *str);
int getchar(void);

typedef struct _FILE FILE;
#ifdef FILE_IS_STRUCT
extern struct _FILE *stdin;
#else
extern FILE *stdin;
#endif

#define bool _Bool

FILE *fopen(const char *name, const char *mode);

int fscanf(FILE *restrict stream, const char *restrict format, ...);
int sprintf(char *str, const char *format, ...);
void setproctitle(const char *fmt, ...);
typedef __typeof(sizeof(int)) size_t;

// Define string functions. Use builtin for some of them. They all default to
// the processing in the taint checker.
#define strcpy(dest, src) \
  ((__builtin_object_size(dest, 0) != -1ULL) \
   ? __builtin___strcpy_chk (dest, src, __builtin_object_size(dest, 1)) \
   : __inline_strcpy_chk(dest, src))

static char *__inline_strcpy_chk (char *dest, const char *src) {
  return __builtin___strcpy_chk(dest, src, __builtin_object_size(dest, 1));
}
char *stpcpy(char *restrict s1, const char *restrict s2);
char *strncpy( char * destination, const char * source, size_t num );
char *strndup(const char *s, size_t n);
char *strncat(char *restrict s1, const char *restrict s2, size_t n);

void *malloc(size_t);
void *calloc(size_t nmemb, size_t size);
void bcopy(void *s1, void *s2, size_t n);

#define BUFSIZE 10

int Buffer[BUFSIZE];
void bufferScanfDirect(void)
{
  int n;
  scanf("%d", &n);
  Buffer[n] = 1; // expected-warning {{Out of bound memory access }}
}

void bufferScanfArithmetic1(int x) {
  int n;
  scanf("%d", &n);
  int m = (n - 3);
  Buffer[m] = 1; // expected-warning {{Out of bound memory access }}
}

void bufferScanfArithmetic2(int x) {
  int n;
  scanf("%d", &n);
  int m = 100 - (n + 3) * x;
  Buffer[m] = 1; // expected-warning {{Out of bound memory access }}
}

void bufferScanfAssignment(int x) {
  int n;
  scanf("%d", &n);
  int m;
  if (x > 0) {
    m = n;
    Buffer[m] = 1; // expected-warning {{Out of bound memory access }}
  }
}

void scanfArg(void) {
  int t = 0;
  scanf("%d", t); // expected-warning {{format specifies type 'int *' but the argument has type 'int'}}
}

void bufferGetchar(int x) {
  int m = getchar();
  Buffer[m] = 1;  //expected-warning {{Out of bound memory access (index is tainted)}}
}

void testUncontrolledFormatString(char **p) {
  char s[80];
  fscanf(stdin, "%s", s);
  char buf[128];
  sprintf(buf,s); // expected-warning {{Uncontrolled Format String}}
  setproctitle(s, 3); // expected-warning {{Uncontrolled Format String}}

  // Test taint propagation through strcpy and family.
  char scpy[80];
  strcpy(scpy, s);
  sprintf(buf,scpy); // expected-warning {{Uncontrolled Format String}}

  stpcpy(*(++p), s); // this generates __inline.
  setproctitle(*(p), 3); // expected-warning {{Uncontrolled Format String}}

  char spcpy[80];
  stpcpy(spcpy, s);
  setproctitle(spcpy, 3); // expected-warning {{Uncontrolled Format String}}

  char *spcpyret;
  spcpyret = stpcpy(spcpy, s);
  setproctitle(spcpyret, 3); // expected-warning {{Uncontrolled Format String}}

  char sncpy[80];
  strncpy(sncpy, s, 20);
  setproctitle(sncpy, 3); // expected-warning {{Uncontrolled Format String}}

  char *dup;
  dup = strndup(s, 20);
  setproctitle(dup, 3); // expected-warning {{Uncontrolled Format String}}

}

int system(const char *command);
void testTaintSystemCall(void) {
  char buffer[156];
  char addr[128];
  scanf("%s", addr);
  system(addr); // expected-warning {{Untrusted data is passed to a system call}}

  // Test that spintf transfers taint.
  sprintf(buffer, "/bin/mail %s < /tmp/email", addr);
  system(buffer); // expected-warning {{Untrusted data is passed to a system call}}
}

void testTaintSystemCall2(void) {
  // Test that snpintf transfers taint.
  char buffern[156];
  char addr[128];
  scanf("%s", addr);
  __builtin_snprintf(buffern, 10, "/bin/mail %s < /tmp/email", addr);
  system(buffern); // expected-warning {{Untrusted data is passed to a system call}}
}

void testTaintSystemCall3(void) {
  char buffern2[156];
  int numt;
  char addr[128];
  scanf("%s %d", addr, &numt);
  __builtin_snprintf(buffern2, numt, "/bin/mail %s < /tmp/email", "abcd");
  system(buffern2); // expected-warning {{Untrusted data is passed to a system call}}
}

void testGets(void) {
  char str[50];
  gets(str);
  system(str); // expected-warning {{Untrusted data is passed to a system call}}
}

void testTaintedBufferSize(void) {
  size_t ts;
  scanf("%zd", &ts);

  int *buf1 = (int*)malloc(ts*sizeof(int)); // expected-warning {{Untrusted data is used to specify the buffer size}}
  char *dst = (char*)calloc(ts, sizeof(char)); //expected-warning {{Untrusted data is used to specify the buffer size}}
  bcopy(buf1, dst, ts); // expected-warning {{Untrusted data is used to specify the buffer size}}
  __builtin_memcpy(dst, buf1, (ts + 4)*sizeof(char)); // expected-warning {{Untrusted data is used to specify the buffer size}}

  // If both buffers are trusted, do not issue a warning.
  char *dst2 = (char*)malloc(ts*sizeof(char)); // expected-warning {{Untrusted data is used to specify the buffer size}}
  strncat(dst2, dst, ts); // no-warning
}

#define AF_UNIX   1   /* local to host (pipes) */
#define AF_INET   2   /* internetwork: UDP, TCP, etc. */
#define AF_LOCAL  AF_UNIX   /* backward compatibility */
#define SOCK_STREAM 1
int socket(int, int, int);
size_t read(int, void *, size_t);
int  execl(const char *, const char *, ...);

void testSocket(void) {
  int sock;
  char buffer[100];

  sock = socket(AF_INET, SOCK_STREAM, 0);
  read(sock, buffer, 100);
  execl(buffer, "filename", 0); // expected-warning {{Untrusted data is passed to a system call}}

  sock = socket(AF_LOCAL, SOCK_STREAM, 0);
  read(sock, buffer, 100);
  execl(buffer, "filename", 0); // no-warning

  sock = socket(AF_INET, SOCK_STREAM, 0);
  // References to both buffer and &buffer as an argument should taint the argument
  read(sock, &buffer, 100);
  execl(buffer, "filename", 0); // expected-warning {{Untrusted data is passed to a system call}}
}

void testStruct(void) {
  struct {
    char buf[16];
    int length;
  } tainted;

  char buffer[16];
  int sock;

  sock = socket(AF_INET, SOCK_STREAM, 0);
  read(sock, &tainted, sizeof(tainted));
  __builtin_memcpy(buffer, tainted.buf, tainted.length); // expected-warning {{Untrusted data is used to specify the buffer size}}
}

void testStructArray(void) {
  struct {
    int length;
  } tainted[4];

  char dstbuf[16], srcbuf[16];
  int sock;

  sock = socket(AF_INET, SOCK_STREAM, 0);
  __builtin_memset(srcbuf, 0, sizeof(srcbuf));

  read(sock, &tainted[0], sizeof(tainted));
  __builtin_memcpy(dstbuf, srcbuf, tainted[0].length); // expected-warning {{Untrusted data is used to specify the buffer size}}

  __builtin_memset(&tainted, 0, sizeof(tainted));
  read(sock, &tainted, sizeof(tainted));
  __builtin_memcpy(dstbuf, srcbuf, tainted[0].length); // expected-warning {{Untrusted data is used to specify the buffer size}}

  __builtin_memset(&tainted, 0, sizeof(tainted));
  // If we taint element 1, we should not raise an alert on taint for element 0 or element 2
  read(sock, &tainted[1], sizeof(tainted));
  __builtin_memcpy(dstbuf, srcbuf, tainted[0].length); // no-warning
  __builtin_memcpy(dstbuf, srcbuf, tainted[2].length); // no-warning
}

void testUnion(void) {
  union {
    int x;
    char y[4];
  } tainted;

  char buffer[4];

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  read(sock, &tainted.y, sizeof(tainted.y));
  // FIXME: overlapping regions aren't detected by isTainted yet
  __builtin_memcpy(buffer, tainted.y, tainted.x);
}

int testDivByZero(void) {
  int x;
  scanf("%d", &x);
  return 5/x; // expected-warning {{Division by a tainted value, possibly zero}}
}

// Zero-sized VLAs.
void testTaintedVLASize(void) {
  int x;
  scanf("%d", &x);
  int vla[x]; // expected-warning{{Declared variable-length array (VLA) has tainted size}}
}

// This computation used to take a very long time.
#define longcmp(a,b,c) { \
  a -= c;  a ^= c;  c += b; b -= a;  b ^= (a<<6) | (a >> (32-b));  a += c; c -= b;  c ^= b;  b += a; \
  a -= c;  a ^= c;  c += b; b -= a;  b ^= a;  a += c; c -= b;  c ^= b;  b += a; }

unsigned radar11369570_hanging(const unsigned char *arr, int l) {
  unsigned a, b, c;
  a = b = c = 0x9899e3 + l;
  while (l >= 6) {
    unsigned t;
    scanf("%d", &t);
    a += b;
    a ^= a;
    a += (arr[3] + ((unsigned) arr[2] << 8) + ((unsigned) arr[1] << 16) + ((unsigned) arr[0] << 24));
    longcmp(a, t, c);
    l -= 12;
  }
  return 5/a; // expected-warning {{Division by a tainted value, possibly zero}}
}

// Check that we do not assert of the following code.
int SymSymExprWithDiffTypes(void* p) {
  int i;
  scanf("%d", &i);
  int j = (i % (int)(long)p);
  return 5/j; // expected-warning {{Division by a tainted value, possibly zero}}
}


void constraintManagerShouldTreatAsOpaque(int rhs) {
  int i;
  scanf("%d", &i);
  // This comparison used to hit an assertion in the constraint manager,
  // which didn't handle NonLoc sym-sym comparisons.
  if (i < rhs)
    return;
  if (i < rhs)
    *(volatile int *) 0; // no-warning
}

int sprintf_is_not_a_source(char *buf, char *msg) {
  int x = sprintf(buf, "%s", msg); // no-warning
  return 1 / x; // no-warning: 'sprintf' is not a taint source
}

int sprintf_propagates_taint(char *buf, char *msg) {
  scanf("%s", msg);
  int x = sprintf(buf, "%s", msg); // propagate taint!
  return 1 / x; // expected-warning {{Division by a tainted value, possibly zero}}
}

int scanf_s(const char *format, ...);
int scanf_s_is_source(int *out) {
  scanf_s("%d", out);
  return 1 / *out; // expected-warning {{Division by a tainted value, possibly zero}}
}

int getopt(int argc, char *const argv[], const char *optstring);
int getopt_is_source(int argc, char **argv) {
  int opt = getopt(argc, argv, "nt:");
  return 1 / opt; // expected-warning {{Division by a tainted value, possibly zero}}
}

struct option {
  const char *name;
  int has_arg;
  int *flag;
  int val;
};
int getopt_long(int argc, char *const argv[], const char *optstring, const struct option *longopts, int *longindex);
int getopt_long_is_source(int argc, char **argv) {
  int option_index = 0;
  struct option long_opts[] = {{0, 0, 0, 0}};
  int opt = getopt_long(argc, argv, "a:b:02", long_opts, &option_index);
  return 1 / opt; // expected-warning {{Division by a tainted value, possibly zero}}
}

int getopt_long_only(int argc, char *const argv[], const char *optstring, const struct option *longopts, int *longindex);
int getopt_long_only_is_source(int argc, char **argv) {
  int option_index = 0;
  struct option long_opts[] = {{0, 0, 0, 0}};
  int opt = getopt_long_only(argc, argv, "a:b:02", long_opts, &option_index);
  return 1 / opt; // expected-warning {{Division by a tainted value, possibly zero}}
}

#define _IO_FILE FILE
int _IO_getc(_IO_FILE *__fp);
int underscore_IO_getc_is_source(_IO_FILE *fp) {
  char c = _IO_getc(fp);
  return 1 / c; // expected-warning {{Division by a tainted value, possibly zero}}
}

char *getcwd(char *buf, size_t size);
int getcwd_is_source(char *buf, size_t size) {
  char *c = getcwd(buf, size);
  return system(c); // expected-warning {{Untrusted data is passed to a system call}}
}

char *getwd(char *buf);
int getwd_is_source(char *buf) {
  char *c = getwd(buf);
  return system(c); // expected-warning {{Untrusted data is passed to a system call}}
}

typedef signed long long ssize_t;
ssize_t readlink(const char *path, char *buf, size_t bufsiz);
int readlink_is_source(char *path, char *buf, size_t bufsiz) {
  ssize_t s = readlink(path, buf, bufsiz);
  system(buf);  // expected-warning {{Untrusted data is passed to a system call}}
  return 1 / s; // expected-warning {{Division by a tainted value, possibly zero}}
}

char *get_current_dir_name(void);
int get_current_dir_name_is_source() {
  char *d = get_current_dir_name();
  return system(d); // expected-warning {{Untrusted data is passed to a system call}}
}

int gethostname(char *name, size_t len);
int gethostname_is_source(char *name, size_t len) {
  gethostname(name, len);
  return system(name); // expected-warning {{Untrusted data is passed to a system call}}
}

struct sockaddr;
typedef size_t socklen_t;
int getnameinfo(const struct sockaddr *restrict addr, socklen_t addrlen,
                       char *restrict host, socklen_t hostlen,
                       char *restrict serv, socklen_t servlen, int flags);
int getnameinfo_is_source(const struct sockaddr *restrict addr, socklen_t addrlen,
                       char *restrict host, socklen_t hostlen,
                       char *restrict serv, socklen_t servlen, int flags) {
  getnameinfo(addr, addrlen, host, hostlen, serv, servlen, flags);

  system(host); // expected-warning {{Untrusted data is passed to a system call}}
  return system(serv); // expected-warning {{Untrusted data is passed to a system call}}
}

int getseuserbyname(const char *linuxuser, char **selinuxuser, char **level);
int getseuserbyname_is_source(const char* linuxuser, char **selinuxuser, char**level) {
  getseuserbyname(linuxuser, selinuxuser, level);
  system(selinuxuser[0]); // expected-warning {{Untrusted data is passed to a system call}}
  return system(level[0]);// expected-warning {{Untrusted data is passed to a system call}}
}

typedef int gid_t;
int getgroups(int size, gid_t list[]);
int getgroups_is_source(int size, gid_t list[]) {
  getgroups(size, list);
  return 1 / list[0]; // expected-warning {{Division by a tainted value, possibly zero}}
}

char *getlogin(void);
int getlogin_is_source() {
  char* n = getlogin();
  return system(n); // expected-warning {{Untrusted data is passed to a system call}}
}

int getlogin_r(char* buf, size_t bufsize);
int getlogin_r_is_source(char* buf, size_t bufsize) {
  getlogin_r(buf, bufsize);
  return system(buf); // expected-warning {{Untrusted data is passed to a system call}}
}

int fscanf_s(FILE *stream, const char *format, ...);
int testFscanf_s(const char *fname, int *d) {
  FILE *f = fopen(fname, "r");
  fscanf_s(f, "%d", d);
  return 1 / *d; // expected-warning {{Division by a tainted value, possibly zero}}
}

int vscanf(const char *format, ...);
int testVscanf(int *d) {
  char format[10];
  scanf("%9s", format); // fake a tainted a file descriptor

  vscanf(format, &d);
  return 1 / *d; // expected-warning {{Division by a tainted value, possibly zero}}
}

int vfscanf(FILE *stream, const char *format, ...);
int testVfscanf(const char *fname, int *d) {
  FILE *f = fopen(fname, "r");
  vfscanf(f, "%d", d);
  return 1 / *d; // expected-warning {{Division by a tainted value, possibly zero}}
}

int fread(void *buffer, size_t size, size_t count, FILE *stream);
int testFread(const char *fname, int *buffer, size_t size, size_t count) {
  FILE *f = fopen(fname, "r");
  size_t read = fread(buffer, size, count, f);

  if (some_global_flag_to_branch_on) // just to have 2 branches, and assert 2 division by zero messages
    return 1 / *buffer;              // expected-warning {{Division by a tainted value, possibly zero}}

  return 1 / read; // expected-warning {{Division by a tainted value, possibly zero}}
}

struct iovec {
  void *iov_base; /* Starting address */
  size_t iov_len; /* Number of bytes to transfer */
};
ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
int testReadv(const struct iovec *iov, int iovcnt) {
  int fd;
  scanf("%d", &fd); // fake a tainted a file descriptor

  size_t read = readv(fd, iov, iovcnt);
  // FIXME: should be able to assert that iov is also tainted
  return 1 / read; // expected-warning {{Division by a tainted value, possibly zero}}
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags);
int testRecv(int *buf, size_t len, int flags) {
  int fd;
  scanf("%d", &fd); // fake a tainted a file descriptor

  size_t read = recv(fd, buf, len, flags);
  if (some_global_flag_to_branch_on) // just to have 2 branches, and assert 2 division by zero messages
    return 1 / *buf;                 // expected-warning {{Division by a tainted value, possibly zero}}

  return 1 / read; // expected-warning {{Division by a tainted value, possibly zero}}
}

ssize_t recvfrom(int sockfd, void *restrict buf, size_t len, int flags,
                 struct sockaddr *restrict src_addr,
                 socklen_t *restrict addrlen);
int testRecvfrom(int *restrict buf, size_t len, int flags,
                 struct sockaddr *restrict src_addr,
                 socklen_t *restrict addrlen) {
  int fd;
  scanf("%d", &fd); // fake a tainted a file descriptor

  size_t read = recvfrom(fd, buf, len, flags, src_addr, addrlen);
  if (some_global_flag_to_branch_on) // just to have 2 branches, and assert 2 division by zero messages
    return 1 / *buf;                 // expected-warning {{Division by a tainted value, possibly zero}}

  return 1 / read; // expected-warning {{Division by a tainted value, possibly zero}}
}

char *ttyname(int fd);
int testTtyname() {
  int fd;
  scanf("%d", &fd); // fake a tainted a file descriptor

  char *name = ttyname(fd);
  return system(name); // expected-warning {{Untrusted data is passed to a system call}}
}

int ttyname_r(int fd, char *buf, size_t buflen);
int testTtyname_r(char *buf, size_t buflen) {
  int fd;
  scanf("%d", &fd); // fake a tainted a file descriptor

  int result = ttyname_r(fd, buf, buflen);
  system(buf);       // expected-warning {{Untrusted data is passed to a system call}}
  return 1 / result; // expected-warning {{Division by a tainted value, possibly zero}}
}

char *dirname(char *path);
int testDirname() {
  char buf[10];
  scanf("%9s", buf);

  char *name = dirname(buf);
  return system(name); // expected-warning {{Untrusted data is passed to a system call}}
}

char *basename(char *path);
int testBasename() {
  char buf[10];
  scanf("%9s", buf);

  char *name = basename(buf);
  return system(name); // expected-warning {{Untrusted data is passed to a system call}}
}

int fnmatch(const char *pattern, const char *string, int flags);
int testFnmatch(const char *string, int flags) {
  char buf[10];
  scanf("%9s", buf);

  int result = fnmatch(buf, string, flags);
  return 1 / result; // expected-warning {{Division by a tainted value, possibly zero}}
}

void *memchr(const void *s, int c, size_t n);
int testMemchr(int c, size_t n) {
  char buf[10];
  scanf("%9s", buf);

  char *result = memchr(buf, c, n);
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}
}

void *memrchr(const void *s, int c, size_t n);
int testMemrchr(int c, size_t n) {
  char buf[10];
  scanf("%9s", buf);

  char *result = memrchr(buf, c, n);
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}
}

void *rawmemchr(const void *s, int c);
int testRawmemchr(int c) {
  char buf[10];
  scanf("%9s", buf);

  char *result = rawmemchr(buf, c);
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}
}

typedef char wchar_t;
int mbtowc(wchar_t *pwc, const char *s, size_t n);
int testMbtowc(wchar_t *pwc, size_t n) {
  char buf[10];
  scanf("%9s", buf);

  int result = mbtowc(pwc, buf, n);
  if (some_global_flag_to_branch_on) // just to have 2 branches, and assert 2 division by zero messages
    return 1 / *pwc;                 // expected-warning {{Division by a tainted value, possibly zero}}

  return 1 / result; // expected-warning {{Division by a tainted value, possibly zero}}
}

int wctomb(char *s, wchar_t wc);
int testWctomb(char *buf) {
  wchar_t wc;
  scanf("%c", &wc);

  int result = wctomb(buf, wc);
  if (some_global_flag_to_branch_on) // just to have 2 branches, and assert 2 division by zero messages
    return 1 / *buf;                 // expected-warning {{Division by a tainted value, possibly zero}}

  return 1 / result; // expected-warning {{Division by a tainted value, possibly zero}}
}

int wcwidth(wchar_t c);
int testWcwidth() {
  wchar_t wc;
  scanf("%c", &wc);

  int width = wcwidth(wc);
  return 1 / width; // expected-warning {{Division by a tainted value, possibly zero}}
}

int memcmp(const void *s1, const void *s2, size_t n);
int testMemcmpWithLHSTainted(size_t n, char *rhs) {
  char lhs[10];
  scanf("%9s", lhs);

  int cmp_result = memcmp(lhs, rhs, n);
  return 1 / cmp_result; // expected-warning {{Division by a tainted value, possibly zero}}
}

int testMemcmpWithRHSTainted(size_t n, char *lhs) {
  char rhs[10];
  scanf("%9s", rhs);

  int cmp_result = memcmp(lhs, rhs, n);
  return 1 / cmp_result; // expected-warning {{Division by a tainted value, possibly zero}}
}

void *memcpy(void *restrict dest, const void *restrict src, size_t n);
int testMemcpy(char *dst, size_t n) {
  char src[10];
  scanf("%9s", src);

  char *result = memcpy(dst, src, n);

  system(dst);           // expected-warning {{Untrusted data is passed to a system call}}
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}
}

void *memmove(void *dest, const void *src, size_t n);
int testMemmove(char *dst, size_t n) {
  char src[10];
  scanf("%9s", src);

  char *result = memmove(dst, src, n);

  system(dst);           // expected-warning {{Untrusted data is passed to a system call}}
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}
}

void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
int testMemmem(const void *needle, size_t needlelen) {
  char haystack[10];
  scanf("%9s", haystack);

  char *result = memmem(haystack, 9, needle, needlelen);
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}
}

char *strstr(const char *haystack, const char *needle);
int testStrstr(const char *needle) {
  char haystack[10];
  scanf("%9s", haystack);

  char *result = strstr(haystack, needle);
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}
}

char *strcasestr(const char *haystack, const char *needle);
int testStrcasestr(const char *needle) {
  char haystack[10];
  scanf("%9s", haystack);

  char *result = strcasestr(haystack, needle);
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}
}

char *strchrnul(const char *s, int c);
int testStrchrnul() {
  char s[10];
  scanf("%9s", s);

  char *result = strchrnul(s, 9);
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}
}

char *index(const char *s, int c);
int testIndex() {
  char s[10];
  scanf("%9s", s);

  char *result = index(s, 9);
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}
}

char *rindex(const char *s, int c);
int testRindex() {
  char s[10];
  scanf("%9s", s);

  char *result = rindex(s, 9);
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}
}

int strcmp(const char *s1, const char *s2);
int testStrcmpWithLHSTainted(char *rhs) {
  char lhs[10];
  scanf("%9s", lhs);

  int cmp_result = strcmp(lhs, rhs);
  return 1 / cmp_result; // expected-warning {{Division by a tainted value, possibly zero}}
}

int testStrcmpWithRHSTainted(char *lhs) {
  char rhs[10];
  scanf("%9s", rhs);

  int cmp_result = strcmp(lhs, rhs);
  return 1 / cmp_result; // expected-warning {{Division by a tainted value, possibly zero}}
}
int strcasecmp(const char *s1, const char *s2);
int testStrcasecmpWithLHSTainted(char *rhs) {
  char lhs[10];
  scanf("%9s", lhs);

  int cmp_result = strcasecmp(lhs, rhs);
  return 1 / cmp_result; // expected-warning {{Division by a tainted value, possibly zero}}
}

int testStrcasecmpWithRHSTainted(char *lhs) {
  char rhs[10];
  scanf("%9s", rhs);

  int cmp_result = strcasecmp(lhs, rhs);
  return 1 / cmp_result; // expected-warning {{Division by a tainted value, possibly zero}}
}
int strncmp(const char *s1, const char *s2, size_t n);
int testStrncmpWithLHSTainted(char *rhs, size_t n) {
  char lhs[10];
  scanf("%9s", lhs);

  int cmp_result = strncmp(lhs, rhs, n);
  return 1 / cmp_result; // expected-warning {{Division by a tainted value, possibly zero}}
}

int testStrncmpWithRHSTainted(char *lhs, size_t n) {
  char rhs[10];
  scanf("%9s", rhs);

  int cmp_result = strncmp(lhs, rhs, n);
  return 1 / cmp_result; // expected-warning {{Division by a tainted value, possibly zero}}
}

int testStrncmpWithNTainted(char *lhs, char *rhs) {
  int n;
  scanf("%d", &n);

  int cmp_result = strncmp(lhs, rhs, n);
  return 1 / cmp_result; // expected-warning {{Division by a tainted value, possibly zero}}
}

int strncasecmp(const char *s1, const char *s2, size_t n);
int testStrncasecmpWithLHSTainted(char *rhs, size_t n) {
  char lhs[10];
  scanf("%9s", lhs);

  int cmp_result = strncmp(lhs, rhs, n);
  return 1 / cmp_result; // expected-warning {{Division by a tainted value, possibly zero}}
}

int testStrncasecmpWithRHSTainted(char *lhs, size_t n) {
  char rhs[10];
  scanf("%9s", rhs);

  int cmp_result = strncmp(lhs, rhs, n);
  return 1 / cmp_result; // expected-warning {{Division by a tainted value, possibly zero}}
}

int testStrncasecmpWithNTainted(char *lhs, char *rhs) {
  int n;
  scanf("%d", &n);

  int cmp_result = strncmp(lhs, rhs, n);
  return 1 / cmp_result; // expected-warning {{Division by a tainted value, possibly zero}}
}

size_t strspn(const char *s, const char *accept);
int testStrspn(const char *accept) {
  char s[10];
  scanf("%9s", s);

  size_t result = strspn(s, accept);
  return 1 / result; // expected-warning {{Division by a tainted value, possibly zero}}
}

size_t strcspn(const char *s, const char *reject);
int testStrcspn(const char *reject) {
  char s[10];
  scanf("%9s", s);

  size_t result = strcspn(s, reject);
  return 1 / result; // expected-warning {{Division by a tainted value, possibly zero}}
}

char *strpbrk(const char *s, const char *accept);
int testStrpbrk(const char *accept) {
  char s[10];
  scanf("%9s", s);

  char *result = strpbrk(s, accept);
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}}
}

char *strndup(const char *s, size_t n);
int testStrndup(size_t n) {
  char s[10];
  scanf("%9s", s);

  char *result = strndup(s, n);
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}}
}

char *strdupa(const char *s);
int testStrdupa() {
  char s[10];
  scanf("%9s", s);

  char *result = strdupa(s);
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}}
}

char *strndupa(const char *s, size_t n);
int testStrndupa(size_t n) {
  char s[10];
  scanf("%9s", s);

  char *result = strndupa(s, n);
  return system(result); // expected-warning {{Untrusted data is passed to a system call}}}
}

size_t strlen(const char *s);
int testStrlen() {
  char s[10];
  scanf("%9s", s);

  size_t result = strlen(s);
  return 1 / result; // expected-warning {{Division by a tainted value, possibly zero}}
}

size_t strnlen(const char *s, size_t maxlen);
int testStrnlen(size_t maxlen) {
  char s[10];
  scanf("%9s", s);

  size_t result = strnlen(s, maxlen);
  return 1 / result; // expected-warning {{Division by a tainted value, possibly zero}}
}

long strtol(const char *restrict nptr, char **restrict endptr, int base);
int testStrtol(char **restrict endptr, int base) {
  char s[10];
  scanf("%9s", s);

  long result = strtol(s, endptr, base);
  system(*endptr); // expected-warning {{Untrusted data is passed to a system call}}}
  return 1 / result; // expected-warning {{Division by a tainted value, possibly zero}}
}

long long strtoll(const char *restrict nptr, char **restrict endptr, int base);
int testStrtoll(char **restrict endptr, int base) {
  char s[10];
  scanf("%9s", s);

  long long result = strtoll(s, endptr, base);
  system(*endptr); // expected-warning {{Untrusted data is passed to a system call}}}
  return 1 / result; // expected-warning {{Division by a tainted value, possibly zero}}
}

unsigned long int strtoul(const char *nptr, char **endptr, int base);
int testStrtoul(char **restrict endptr, int base) {
  char s[10];
  scanf("%9s", s);

  unsigned long result = strtoul(s, endptr, base);
  system(*endptr); // expected-warning {{Untrusted data is passed to a system call}}}
  return 1 / result; // expected-warning {{Division by a tainted value, possibly zero}}
}
unsigned long long int strtoull(const char *nptr, char **endptr, int base);
int testStrtoull(char **restrict endptr, int base) {
  char s[10];
  scanf("%9s", s);

  unsigned long long result = strtoull(s, endptr, base);
  system(*endptr); // expected-warning {{Untrusted data is passed to a system call}}}
  return 1 / result; // expected-warning {{Division by a tainted value, possibly zero}}
}

int isalnum(int c);
int testIsalnum() {
  char c;
  scanf("%c", &c);

  return 1 / isalnum(c); // expected-warning {{Division by a tainted value, possibly zero}}
}
int isalpha(int c);
int testIsalpha() {
  char c;
  scanf("%c", &c);

  return 1 / isalpha(c); // expected-warning {{Division by a tainted value, possibly zero}}
}
int isascii(int c);
int testIsascii() {
  char c;
  scanf("%c", &c);

  return 1 / isascii(c); // expected-warning {{Division by a tainted value, possibly zero}}
}
int isblank(int c);
int testIsblank() {
  char c;
  scanf("%c", &c);

  return 1 / isblank(c); // expected-warning {{Division by a tainted value, possibly zero}}
}
int iscntrl(int c);
int testIsctrl() {
  char c;
  scanf("%c", &c);

  return 1 / iscntrl(c); // expected-warning {{Division by a tainted value, possibly zero}}
}
int isdigit(int c);
int testIsdigit() {
  char c;
  scanf("%c", &c);

  return 1 / isdigit(c); // expected-warning {{Division by a tainted value, possibly zero}}
}

int isgraph(int c);
int testIsgraph() {
  char c;
  scanf("%c", &c);

  return 1 / isgraph(c); // expected-warning {{Division by a tainted value, possibly zero}}
}
int islower(int c);
int testIslower() {
  char c;
  scanf("%c", &c);

  return 1 / islower(c); // expected-warning {{Division by a tainted value, possibly zero}}
}
int isprint(int c);
int testIssprint() {
  char c;
  scanf("%c", &c);

  return 1 / isprint(c); // expected-warning {{Division by a tainted value, possibly zero}}
}
int ispunct(int c);
int testIspunct() {
  char c;
  scanf("%c", &c);

  return 1 / ispunct(c); // expected-warning {{Division by a tainted value, possibly zero}}
}
int isspace(int c);
int testIsspace() {
  char c;
  scanf("%c", &c);

  return 1 / isspace(c); // expected-warning {{Division by a tainted value, possibly zero}}
}
int isupper(int c);
int testIsupper() {
  char c;
  scanf("%c", &c);

  return 1 / isupper(c); // expected-warning {{Division by a tainted value, possibly zero}}
}
int isxdigit(int c);
int testIsxdigit() {
  char c;
  scanf("%c", &c);

  return 1 / isxdigit(c); // expected-warning {{Division by a tainted value, possibly zero}}
}

int cmp_less(const void *lhs, const void *rhs) {
  return *(int *)lhs < *(int *)rhs ? -1 : *(int *)lhs > *(int *)rhs ? 1
                                                                    : 0;
}
void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
int testQsort() {
  int data[6];
  scanf("%d %d %d %d %d %d", data, data + 1, data + 2, data + 3, data + 4, data + 5);

  qsort(data, sizeof(data), sizeof(data[0]), &cmp_less);
  return 1 / data[0]; // expected-warning {{Division by a tainted value, possibly zero}}
}

int cmp_less_than(const void *lhs, const void *rhs, void *baseline) {
  return *(int *)lhs < *(int *)baseline ? -1 : *(int *)lhs > *(int *)baseline ? 1
                                                                              : 0;
}
void qsort_r(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *, void *), void *arg);
int testQsort_r() {
  int data[6];
  scanf("%d %d %d %d %d %d", data, data + 1, data + 2, data + 3, data + 4, data + 5);

  int baseline = 42;

  qsort_r(data, sizeof(data), sizeof(data[0]), &cmp_less_than, &baseline);
  return 1 / data[0]; // expected-warning {{Division by a tainted value, possibly zero}}
}

// Test configuration
int mySource1(void);
void mySource2(int*);
void myScanf(const char*, ...);
int myPropagator(int, int*);
int mySnprintf(char*, size_t, const char*, ...);
bool isOutOfRange(const int*);
void mySink(int, int, int);

void testConfigurationSources1(void) {
  int x = mySource1();
  Buffer[x] = 1; // expected-warning {{Out of bound memory access }}
}

void testConfigurationSources2(void) {
  int x;
  mySource2(&x);
  Buffer[x] = 1; // expected-warning {{Out of bound memory access }}
}

void testConfigurationSources3(void) {
  int x, y;
  myScanf("%d %d", &x, &y);
  Buffer[y] = 1; // expected-warning {{Out of bound memory access }}
}

void testConfigurationPropagation(void) {
  int x = mySource1();
  int y;
  myPropagator(x, &y);
  Buffer[y] = 1; // expected-warning {{Out of bound memory access }}
}

void testConfigurationFilter(void) {
  int x = mySource1();
  if (isOutOfRange(&x)) // the filter function
    return;
  Buffer[x] = 1; // no-warning
}

void testConfigurationSinks(void) {
  int x = mySource1();
  mySink(x, 1, 2);
  // expected-warning@-1 {{Untrusted data is passed to a user-defined sink}}
  mySink(1, x, 2); // no-warning
  mySink(1, 2, x);
  // expected-warning@-1 {{Untrusted data is passed to a user-defined sink}}
}

void testUnknownFunction(void (*foo)(void)) {
  foo(); // no-crash
}
