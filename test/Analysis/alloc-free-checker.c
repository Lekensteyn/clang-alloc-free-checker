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
  char *p = (char *)g_malloc(42);
} // expected-warning {{Memory leak}}

void checkFreeMismatch() {
  char **p = g_strsplit("", "", -1);
  g_free(p); // expected-warning {{Memory is expected to be deallocated by g_strfreev}}
}

void checkListFreeMismatch() {
  char **p = (char **)g_malloc(42);
  g_strfreev(p); // expected-warning {{Memory is expected to be deallocated by g_free}}
}
