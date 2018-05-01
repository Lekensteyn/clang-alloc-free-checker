#pragma clang system_header

typedef void *gpointer;
typedef const void *gconstpointer;
typedef unsigned long gsize;
typedef char gchar;
typedef int gint;
typedef unsigned int guint;

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
