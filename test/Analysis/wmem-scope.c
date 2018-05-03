// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.AllocFree -verify %s

#include "Inputs/glib-header.h"
#include "Inputs/wmem-header.h"

void checkNullScopeMatch() {
  char *p = (char *)wmem_alloc(NULL, 42);
  wmem_free(NULL, p);
}

void checkEpanScopeMatch() {
  char *p = (char *)wmem_alloc(wmem_epan_scope(), 42);
  wmem_free(wmem_epan_scope(), p);
}

void checkPacketScopeMatch() {
  char *p = (char *)wmem_alloc(wmem_packet_scope(), 42);
  wmem_free(wmem_packet_scope(), p);
}

void checkFileScopeMatch() {
  char *p = (char *)wmem_alloc((wmem_file_scope()), 42);
  wmem_free(wmem_file_scope(), p);
}

void checkNullScopeMismatch() {
  char *p = (char *)wmem_alloc(NULL, 42);
  wmem_free(wmem_epan_scope(), p); // expected-warning {{Memory is expected to be deallocated by wmem_free(NULL, ...)}}
}

void checkEpanScopeMismatch() {
  char *p = (char *)wmem_alloc(wmem_epan_scope(), 42);
  wmem_free(NULL, p); // expected-warning {{Memory is expected to be deallocated by wmem_free(wmem_epan_scope(), ...)}}
}

void checkPacketScopeMismatch() {
  char *p = (char *)wmem_alloc(wmem_packet_scope(), 42);
  wmem_free(wmem_epan_scope(), p); // expected-warning {{Memory is expected to be deallocated by wmem_free(wmem_packet_scope(), ...)}}
}

void checkFileScopeMismatch() {
  char *p = (char *)wmem_alloc(wmem_file_scope(), 42);
  wmem_free(wmem_epan_scope(), p); // expected-warning {{Memory is expected to be deallocated by wmem_free(wmem_file_scope(), ...)}}
}

void checkUnknownScopeMatch(wmem_allocator_t *scope) {
  char *p = (char *)wmem_alloc(scope, 42);
  wmem_free(scope, p);
}

void checkUnknownScopeMismatch(wmem_allocator_t *scope) {
  char *p = (char *)wmem_alloc(scope, 42);
  wmem_free(NULL, p); // expected-warning {{Memory is expected to be deallocated by wmem_free}}
}

void checkUnknownScopeMismatch2(wmem_allocator_t *scope) {
  char *p = (char *)wmem_alloc(wmem_file_scope(), 42);
  wmem_free(scope, p); // expected-warning {{Memory is expected to be deallocated by wmem_free(wmem_file_scope(), ...)}}
}
