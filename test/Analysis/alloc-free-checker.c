// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.AllocFree -verify %s

#include "Inputs/glib-header.h"

void checkNormalFree() {
  char *p = (char *)g_malloc(42);
  g_free(p);
}

void checkNormalListFree() {
  char **p = g_strsplit("", "", -1);
  g_strfreev(p);
}

void checkDoubleFree() {
  char *p = (char *)g_malloc(42);
  g_free(p);
  g_free(p); // expected-warning {{memory was freed before}}
}

void checkMemleak() {
  char *p = (char *)g_malloc0(42);
} // expected-warning {{Memory leak}}

void checkRealloc() {
  char *p = (char *)g_malloc0(42);
  char *p2 = (char *)g_realloc(p, 43);
  g_free(p2);
}

void checkReallocBadFree() {
  char *p = (char *)g_malloc0(42);
  char *p2 = (char *)g_realloc(p, 43);
  g_free(p); // expected-warning {{memory was freed before}}
  g_free(p2);
}

void checkReallocMemleak() {
  char *p = (char *)g_realloc(NULL, 43);
} // expected-warning {{Memory leak}}

void checkFreeMismatch() {
  char **p = g_strsplit("", "", -1);
  g_free(p); // expected-warning {{Memory is expected to be deallocated by g_strfreev}}
}

void checkFreeMismatch2() {
  char **p = g_strsplit("", "", -1);
  char **p2 = g_strdupv(p);
  g_strfreev(p);
  g_free(p2); // expected-warning {{Memory is expected to be deallocated by g_strfreev}}
}

void checkListFreeMismatch() {
  char **p = (char **)g_malloc(42);
  g_strfreev(p); // expected-warning {{Memory is expected to be deallocated by g_free}}
}

void checkListFreeMismatch2() {
  char **p = (char **)g_strdup("");
  g_strfreev(p); // expected-warning {{Memory is expected to be deallocated by g_free}}
}

void checkListFreeMismatch3() {
  char **p = (char **)g_memdup("", 1);
  g_strfreev(p); // expected-warning {{Memory is expected to be deallocated by g_free}}
}

void checkListFreeMismatch4() {
  char **p = (char **)g_strndup("", 1);
  g_strfreev(p); // expected-warning {{Memory is expected to be deallocated by g_free}}
}

void checkIdentityFunction() {
  char *p = g_strdup("");
  // original "p" should not be marked as leaked because g_strdelimit returns the same "p".
  p = g_strdelimit(p, "_", '-');
  g_free(p);
}

void checkNoMemLeaks() {
  char *p = g_strdup("");
  char *p2 = g_strdup(p);
  g_free(p);
  g_free(p2);
}

void checkMemleakEscapedPointer() {
  char *p = g_strdup("");
  // "p" leaks. It should probably not be marked here, but that is what is implemented.
  char *p2 = g_strdup(p); // expected-warning {{Memory leak}}
  g_free(p2);
}

void checkMemleakReportOnce(int flag) {
  char *p = (char *)g_malloc(42);
  if (flag) {
    p[0] = 1;
    return;
  }
  p[0] = 2;
} // expected-warning {{Memory leak}}
