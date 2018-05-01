// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.AllocFree -verify %s

#include "Inputs/glib-header.h"
#include "Inputs/wmem-header.h"

void checkNormalFree() {
  char *p = (char *)wmem_alloc(NULL, 42);
  wmem_free(NULL, p);
}

#if 0
void checkNormalListFree() {
  char **p = wmem_strsplit(NULL, "", "", -1);
  // TODO API design issue: there is no good way to delete elements.
  wmem_free(NULL, p);
}
#endif

void checkDoubleFree() {
  char *p = (char *)wmem_alloc(NULL, 42);
  wmem_free(NULL, p);
  wmem_free(NULL, p); // expected-warning {{memory was freed before}}
}

void checkAllocMemleak() {
  char *p = (char *)wmem_alloc(NULL, 42);
} // expected-warning {{Memory leak}}

void checkAlloc0Memleak() {
  char *p = (char *)wmem_alloc0(NULL, 42);
} // expected-warning {{Memory leak}}

void checkReallocMemleak() {
  char *p = (char *)wmem_alloc0(NULL, 42);
  char *p2 = (char *)wmem_realloc(NULL, p, 43);
} // expected-warning {{Memory leak}}

void checkStrdupMemLeak() {
  gchar *p = wmem_strdup(NULL, "");
} // expected-warning {{Memory leak}}

void checkStrndupMemLeak() {
  gchar *p = wmem_strndup(NULL, "x", 1);
} // expected-warning {{Memory leak}}

void checkStrdup_printfMemLeak() {
  gchar *p = wmem_strdup_printf(NULL, "x");
} // expected-warning {{Memory leak}}

void checkStrdup_vprintfMemLeak(va_list ap) {
  gchar *p = wmem_strdup_vprintf(NULL, "x", ap);
} // expected-warning {{Memory leak}}

void checkStrconcatMemLeak() {
  gchar *p = wmem_strconcat(NULL, "x", "y");
} // expected-warning {{Memory leak}}

void checkStrjoinMemLeak() {
  gchar *p = wmem_strjoin(NULL, ",", "x", "y");
} // expected-warning {{Memory leak}}

void checkStrjoinvMemLeak() {
  gchar *array[] = { "x", "y", NULL };
  gchar *p = wmem_strjoinv(NULL, ",", array);
} // expected-warning {{Memory leak}}

void checkAscii_strdownMemLeak() {
  gchar *p = wmem_ascii_strdown(NULL, "X", 1);
} // expected-warning {{Memory leak}}
