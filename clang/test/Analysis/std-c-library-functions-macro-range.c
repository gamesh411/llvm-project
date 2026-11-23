// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,unix.StdCLibraryFunctions,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -DEOF=0x10000000000000000 -verify=eof %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,unix.StdCLibraryFunctions,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -DEOF=0x100000000 -verify=eof %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,unix.StdCLibraryFunctions,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -DEOF= -verify=eof %s
// RUN: %clang_analyze_cc1 -triple avr \
// RUN:   -analyzer-checker=core,unix.StdCLibraryFunctions,debug.ExprInspection \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -DEOF=0x10000 -verify=eof %s
// RUN: %clang_analyze_cc1 -triple x86_64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,unix.StdCLibraryFunctions \
// RUN:   -analyzer-config unix.StdCLibraryFunctions:ModelPOSIX=true \
// RUN:   -DAT_FDCWD=0xFFFAFDCD -verify=at-fdcwd %s

void clang_analyzer_eval(int);

typedef struct FILE FILE;

// An EOF value that is empty or does not fit into the target's int is ignored,
// and the default value of -1 is used instead. The int of AVR has 16 bits.
int getc(FILE *);
void test_getc(FILE *fp) {
  int y = getc(fp);
  if (y < 0) {
    clang_analyzer_eval(y == -1); // eof-warning{{TRUE}}
  }
}

#ifdef AT_FDCWD
// DragonFly BSD defines AT_FDCWD as 0xFFFAFDCD, which is converted to the int
// parameter of linkat. It replaces the default value of -100.
int linkat(int olddirfd, const char *oldpath, int newdirfd,
           const char *newpath, int flags);
void test_linkat(void) {
  (void)linkat(AT_FDCWD, "from", AT_FDCWD, "to", 0);
  (void)linkat(-100, "from", AT_FDCWD, "to", 0); // at-fdcwd-warning{{The 1st argument to 'linkat' is -100 but should be a valid file descriptor or AT_FDCWD}}
}
#endif
