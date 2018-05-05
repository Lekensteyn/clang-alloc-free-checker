#pragma clang system_header

#define NULL ((void *)0)

typedef void *gpointer;
typedef const void *gconstpointer;
typedef unsigned long gsize;
typedef signed long gssize;
typedef char gchar;
typedef int gint;
typedef unsigned int guint;
typedef gint gboolean;
#define FALSE (0)
#define TRUE (!FALSE)

gpointer g_malloc(gsize n_bytes);
gpointer g_malloc0(gsize n_bytes);
gpointer g_realloc(gpointer mem, gsize n_bytes);
void g_free(gpointer mem);
gpointer g_memdup(gconstpointer mem, guint byte_size);

gpointer g_strdup(const gchar *str);
gchar *g_strndup(const gchar *str, gsize n);

gchar **g_strdupv(gchar **str_array);
gchar **g_strsplit(const gchar *string, const gchar *delimiter,
                   gint max_tokens);
void g_strfreev(gchar **str_array);

gchar *g_strdelimit(gchar *string, const gchar *delimiters,
                    gchar new_delimiter);

/* Arrays */
typedef struct GArray GArray;
GArray *g_array_new(gboolean zero_terminated, gboolean clear_,
                    guint element_size);
GArray *g_array_sized_new(gboolean zero_terminated, gboolean clear_,
                          guint element_size, guint reserved_size);
/* TODO g_array_ref / g_array_unref for? Unused in Wireshark. */
gchar *g_array_free(GArray *array, gboolean free_segment);
