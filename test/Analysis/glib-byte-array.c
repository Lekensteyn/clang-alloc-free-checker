// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.AllocFree -verify %s

#include "Inputs/glib-header.h"

void checkGByteArrayFreeSegmentTrue() {
  GByteArray *array = g_byte_array_new();
  g_byte_array_free(array, TRUE);
}

void checkGByteArrayFreeSegmentFalse() {
  GByteArray *array = g_byte_array_new();
  guint8 *segment = g_byte_array_free(array, FALSE);
  g_free(segment);
}

void checkGByteArrayFreeMismatch() {
  GByteArray *array = g_byte_array_new();
  g_free(array); // expected-warning {{Memory is expected to be deallocated by g_byte_array_free}}
}

void checkMemLeakGByteArrayNew() {
  GByteArray *array = g_byte_array_new();
} // expected-warning {{Memory leak}}

void checkMemLeakGByteArrayNewTake() {
  GByteArray *array = g_byte_array_new_take(NULL, 0);
} // expected-warning {{Memory leak}}

void checkMemLeakGByteArraySizedNew() {
  GByteArray *array = g_byte_array_sized_new(42);
} // expected-warning {{Memory leak}}

void checkMemLeakGByteArrayFree() {
  GByteArray *array = g_byte_array_new();
  g_byte_array_free(array, FALSE);
} // expected-warning {{Memory leak}}

void checkGByteArrayAppendFreeMismatch() {
  GByteArray *array = g_byte_array_append(g_byte_array_new(), NULL, 0);
  g_free(array); // expected-warning {{Memory is expected to be deallocated by g_byte_array_free}}
}

void checkGByteArrayAppendFreeSegmentTrue() {
  GByteArray *array = g_byte_array_append(g_byte_array_new(), NULL, 0);
  g_byte_array_free(array, TRUE);
}

void checkGByteArrayIdentityMemLeaks(const guint8 *data, guint len) {
  GByteArray *array = g_byte_array_append(g_byte_array_new(), NULL, 0);
  array = g_byte_array_append(array, data, len);
  array = g_byte_array_prepend(array, data, len);
  array = g_byte_array_remove_index(array, 0);
  array = g_byte_array_remove_index_fast(array, 0);
  array = g_byte_array_remove_range(array, 0, 1);
  array = g_byte_array_set_size(array, 0);
} // expected-warning {{Memory leak}}

void checkGByteArraySortLeaks(GCompareFunc compare_func, GCompareDataFunc cdf) {
  GByteArray *array = g_byte_array_new();
  g_byte_array_sort(array, compare_func);
  g_byte_array_sort_with_data(array, cdf, NULL);
} // expected-warning {{Memory leak}}
