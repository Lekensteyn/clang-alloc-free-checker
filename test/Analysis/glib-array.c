// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.AllocFree -verify %s

#include "Inputs/glib-header.h"

void checkGArrayFreeSegmentTrue() {
  GArray *array = g_array_new(FALSE, TRUE, sizeof(int));
  g_array_free(array, TRUE);
}

void checkGArrayFreeSegmentFalse() {
  GArray *array = g_array_new(FALSE, TRUE, sizeof(int));
  char *segment = g_array_free(array, FALSE);
  g_free(segment);
}

void checkGArrayFreeMismatch() {
  GArray *array = g_array_new(FALSE, TRUE, sizeof(int));
  g_free(array); // expected-warning {{Memory is expected to be deallocated by g_array_free}}
}

void checkMemLeakGArrayNew() {
  GArray *array = g_array_new(FALSE, TRUE, sizeof(int));
} // expected-warning {{Memory leak}}

void checkMemLeakGArrayFree() {
  GArray *array = g_array_new(FALSE, TRUE, sizeof(int));
  g_array_free(array, FALSE);
} // expected-warning {{Memory leak}}
