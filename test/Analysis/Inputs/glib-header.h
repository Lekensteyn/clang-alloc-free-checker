#pragma clang system_header

// header is taken from Clang source tree.
#include "system-header-simulator-for-valist.h"

#define NULL ((void *)0)

typedef void *gpointer;
typedef const void *gconstpointer;
typedef unsigned long gsize;
typedef signed long gssize;
typedef char gchar;
typedef int gint;
typedef unsigned int guint;
typedef unsigned char guint8;
typedef gint gboolean;
#define FALSE (0)
#define TRUE (!FALSE)
typedef void (*GDestroyNotify)(gpointer data);

gpointer g_malloc(gsize n_bytes);
gpointer g_malloc0(gsize n_bytes);
gpointer g_realloc(gpointer mem, gsize n_bytes);
void g_free(gpointer mem);
gpointer g_memdup(gconstpointer mem, guint byte_size);

/* String Utility Functions */
gpointer g_strdup(const gchar *str);
gchar *g_strndup(const gchar *str, gsize n);
gchar **g_strdupv(gchar **str_array);
gchar *g_strdup_printf(const gchar *format, ...);
gchar *g_strdup_vprintf(const gchar *format, va_list args);
gchar *g_strreverse(gchar *string);
gchar *g_strchug(gchar *string);
gchar *g_strchomp(gchar *string);
gchar *g_strdelimit(gchar *string, const gchar *delimiters,
                    gchar new_delimiter);
gchar *g_strcanon(gchar *string, const gchar *valid_chars, gchar substitutor);
gchar **g_strsplit(const gchar *string, const gchar *delimiter,
                   gint max_tokens);
gchar *g_strdelimit(gchar *string, const gchar *delimiters,
                    gchar new_delimiter);
gchar **g_strsplit_set(const gchar *string, const gchar *delimiters,
                       gint max_tokens);
void g_strfreev(gchar **str_array);
gchar *g_strconcat(const gchar *string1, ...);
gchar *g_strjoin(const gchar *separator, ...);
gchar *g_strjoinv(const gchar *separator, gchar **str_array);

/* Arrays */
typedef struct GArray GArray;
GArray *g_array_new(gboolean zero_terminated, gboolean clear_,
                    guint element_size);
GArray *g_array_sized_new(gboolean zero_terminated, gboolean clear_,
                          guint element_size, guint reserved_size);
/* TODO g_array_ref / g_array_unref for? Unused in Wireshark. */
gchar *g_array_free(GArray *array, gboolean free_segment);

/* Pointer Arrays */
typedef struct GPtrArray GPtrArray;
GPtrArray *g_ptr_array_new(void);
GPtrArray *g_ptr_array_sized_new(guint reserved_size);
GPtrArray *g_ptr_array_new_with_free_func(GDestroyNotify element_free_func);
GPtrArray *g_ptr_array_new_full(guint reserved_size,
                                GDestroyNotify element_free_func);
/* TODO g_ptr_array_ref / g_ptr_array_unref? Unused in Wireshark. */
gpointer *g_ptr_array_free(GPtrArray *array, gboolean free_seg);

/* Byte Arrays */
typedef struct GByteArray GByteArray;
GByteArray *g_byte_array_new(void);
GByteArray *g_byte_array_new_take(guint8 *data, gsize len);
GByteArray *g_byte_array_sized_new(guint reserved_size);
/* TODO g_byte_array_ref / g_byte_array_unref? Unused in Wireshark. */
guint8 *g_byte_array_free(GByteArray *array, gboolean free_segment);
/* TODO g_byte_array_free_to_bytes and GBytes? Unused in Wireshark. */
