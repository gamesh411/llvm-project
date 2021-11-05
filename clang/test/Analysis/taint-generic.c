// RUN: %clang_analyze_cc1 -Wno-format-security -Wno-pointer-to-int-cast -verify %s \
// RUN:   -analyzer-checker=alpha.security.taint \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=alpha.security.ArrayBoundV2 \
// RUN:   -analyzer-config \
// RUN:     alpha.security.taint.TaintPropagation:Config=%S/Inputs/taint-generic-config.yaml

// RUN: %clang_analyze_cc1 -Wno-format-security -Wno-pointer-to-int-cast -verify %s \
// RUN:   -DFILE_IS_STRUCT \
// RUN:   -analyzer-checker=alpha.security.taint \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=alpha.security.ArrayBoundV2 \
// RUN:   -analyzer-config \
// RUN:     alpha.security.taint.TaintPropagation:Config=%S/Inputs/taint-generic-config.yaml

// RUN: not %clang_analyze_cc1 -Wno-pointer-to-int-cast -verify %s \
// RUN:   -analyzer-checker=alpha.security.taint \
// RUN:   -analyzer-config \
// RUN:     alpha.security.taint.TaintPropagation:Config=justguessit \
// RUN:   2>&1 | FileCheck %s -check-prefix=CHECK-INVALID-FILE

// CHECK-INVALID-FILE: (frontend): invalid input for checker option
// CHECK-INVALID-FILE-SAME:        'alpha.security.taint.TaintPropagation:Config',
// CHECK-INVALID-FILE-SAME:        that expects a valid filename instead of
// CHECK-INVALID-FILE-SAME:        'justguessit'

// RUN: not %clang_analyze_cc1 -verify %s \
// RUN:   -analyzer-checker=alpha.security.taint \
// RUN:   -analyzer-config \
// RUN:     alpha.security.taint.TaintPropagation:Config=%S/Inputs/taint-generic-config-ill-formed.yaml \
// RUN:   2>&1 | FileCheck -DMSG=%errc_EINVAL %s -check-prefix=CHECK-ILL-FORMED

// CHECK-ILL-FORMED: (frontend): invalid input for checker option
// CHECK-ILL-FORMED-SAME:        'alpha.security.taint.TaintPropagation:Config',
// CHECK-ILL-FORMED-SAME:        that expects a valid yaml file: [[MSG]]

// RUN: not %clang_analyze_cc1 -verify %s \
// RUN:   -analyzer-checker=alpha.security.taint \
// RUN:   -analyzer-config \
// RUN:     alpha.security.taint.TaintPropagation:Config=%S/Inputs/taint-generic-config-invalid-arg.yaml \
// RUN:   2>&1 | FileCheck %s -check-prefix=CHECK-INVALID-ARG

// CHECK-INVALID-ARG: (frontend): invalid input for checker option
// CHECK-INVALID-ARG-SAME:        'alpha.security.taint.TaintPropagation:Config',
// CHECK-INVALID-ARG-SAME:        that expects an argument number for propagation
// CHECK-INVALID-ARG-SAME:        rules greater or equal to -1

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
