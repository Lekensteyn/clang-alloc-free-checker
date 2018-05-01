#pragma clang system_header

typedef void *gpointer;
typedef unsigned long gsize;
typedef char gchar;
typedef int gint;

gpointer g_malloc(gsize n_bytes);
gpointer g_malloc0(gsize n_bytes);
gpointer g_realloc(gpointer mem, gsize n_bytes);
void g_free(gpointer mem);

gchar **g_strsplit(const gchar *string, const gchar *delimiter,
                   gint max_tokens);
void g_strfreev(gchar **str_array);
