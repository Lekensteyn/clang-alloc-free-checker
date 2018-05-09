#pragma clang system_header

typedef struct tvbuff tvbuff_t;
typedef void (*tvbuff_free_cb_t)(void *);

void tvb_set_free_cb(tvbuff_t *tvb, const tvbuff_free_cb_t func);
tvbuff_t *tvb_new_real_data(const guint8 *data, const guint length,
                            const gint reported_length);
