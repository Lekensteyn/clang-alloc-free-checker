// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.AllocFree -verify %s

#include "Inputs/glib-header.h"

void checkGPtrArrayFreeSegmentTrue() {
  GPtrArray *array = g_ptr_array_new();
  g_ptr_array_free(array, TRUE);
}

void checkGPtrArrayFreeSegmentFalse() {
  GPtrArray *array = g_ptr_array_new();
  gpointer *segment = g_ptr_array_free(array, FALSE);
  g_free(segment);
}

void checkGPtrArrayFreeMismatch() {
  GPtrArray *array = g_ptr_array_new();
  g_free(array); // expected-warning {{Memory is expected to be deallocated by g_ptr_array_free}}
}

void checkMemLeakGPtrArrayNew() {
  GPtrArray *array = g_ptr_array_new();
} // expected-warning {{Memory leak}}

void checkMemLeakGPtrArraySizedNew() {
  GPtrArray *array = g_ptr_array_sized_new(42);
} // expected-warning {{Memory leak}}

void checkMemLeakGPtrArrayNewWithFreeFunc() {
  GPtrArray *array = g_ptr_array_new_with_free_func(NULL);
} // expected-warning {{Memory leak}}

void checkMemLeakGPtrArrayNewFull() {
  GPtrArray *array = g_ptr_array_new_full(42, NULL);
} // expected-warning {{Memory leak}}

void checkMemLeakGPtrArrayFree() {
  GPtrArray *array = g_ptr_array_new();
  g_ptr_array_free(array, FALSE);
} // expected-warning {{Memory leak}}
