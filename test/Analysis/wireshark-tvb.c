// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.AllocFree -verify %s

#include "Inputs/glib-header.h"
#include "Inputs/wmem-header.h"
#include "Inputs/tvbuff-header.h"

void checkTvbWithStaticMemory() {
    const guint8 *data = (const guint8 *)"";
    tvbuff_t *tvb = tvb_new_real_data(data, 0, 0);
    if (data[0]) {
    }
}

void checkTvbWithFreeCb() {
    int n = 100;
    void *data = g_malloc0(n);
    tvbuff_t *tvb = tvb_new_real_data(data, n, n);
    tvb_set_free_cb(tvb, g_free);
}

// TODO UAF detection
#if 0
void checkTvbWithUseAfterFreeData() {
    int n = 100;
    guint8 *data = (guint8 *)g_malloc0(n);
    g_free(data);
    tvbuff_t *tvb = tvb_new_real_data(data, n, n);
}
#endif

// expected-no-diagnostics
