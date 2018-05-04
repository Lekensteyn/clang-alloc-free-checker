// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.AllocFree -verify %s

#include "Inputs/glib-header.h"
#include "Inputs/wmem-header.h"

void checkNormalFree() {
  char *p = (char *)wmem_alloc(NULL, 42);
  wmem_free(NULL, p);
}

void checkNormalListFree() {
  char **p = wmem_strsplit(NULL, "", "", -1);
  // TODO API design issue: there is no good way to delete elements.
  wmem_free(NULL, p); // expected-warning {{Potential memory leak}}
} // expected-warning {{Memory leak}}

void checkPacketScopedListFree() {
  char **p = wmem_strsplit(wmem_packet_scope(), "", "", -1);
  wmem_free(wmem_packet_scope(), p);
}

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

void checkStrsplitMemLeak() {
  gchar **p = wmem_strsplit(NULL, "X", ",", -1);
} // expected-warning {{Memory leak}}

void checkAscii_strdownMemLeak() {
  gchar *p = wmem_ascii_strdown(NULL, "X", 1);
} // expected-warning {{Memory leak}}

void checkBadGFree() {
  char *p = (char *)wmem_alloc(NULL, 42);
  g_free(p); // expected-warning {{Memory is expected to be deallocated by wmem_free(NULL, ...)}}
}

void checkBadWmemFree() {
  char *p = (char *)g_malloc(42);
  wmem_free(NULL, p); // expected-warning {{Memory is expected to be deallocated by g_free}}
}
