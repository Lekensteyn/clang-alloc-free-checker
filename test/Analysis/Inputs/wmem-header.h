#pragma clang system_header

// header is taken from Clang source tree.
#include "system-header-simulator-for-valist.h"

typedef unsigned long size_t;

/* wmem_core.h */
struct _wmem_allocator_t;
typedef struct _wmem_allocator_t wmem_allocator_t;

void *wmem_alloc(wmem_allocator_t *allocator, const size_t size);
void *wmem_alloc0(wmem_allocator_t *allocator, const size_t size);
void wmem_free(wmem_allocator_t *allocator, void *ptr);
void *wmem_realloc(wmem_allocator_t *allocator, void *ptr, const size_t size);

/* wmem_scopes.h */
wmem_allocator_t *wmem_epan_scope(void);
wmem_allocator_t *wmem_packet_scope(void);
wmem_allocator_t *wmem_file_scope(void);

/* wmem_strutl.h */
gchar *wmem_strdup(wmem_allocator_t *allocator, const gchar *src);
gchar *wmem_strndup(wmem_allocator_t *allocator, const gchar *src,
                    const size_t len);
gchar *wmem_strdup_printf(wmem_allocator_t *allocator, const gchar *fmt, ...);
gchar *wmem_strdup_vprintf(wmem_allocator_t *allocator, const gchar *fmt,
                           va_list ap);
gchar *wmem_strconcat(wmem_allocator_t *allocator, const gchar *first, ...);
gchar *wmem_strjoin(wmem_allocator_t *allocator, const gchar *separator,
                    const gchar *first, ...);
gchar *wmem_strjoinv(wmem_allocator_t *allocator, const gchar *separator,
                     gchar **str_array);
gchar **wmem_strsplit(wmem_allocator_t *allocator, const gchar *src,
                      const gchar *delimiter, int max_tokens);
gchar *wmem_ascii_strdown(wmem_allocator_t *allocator, const gchar *str,
                          gssize len);
