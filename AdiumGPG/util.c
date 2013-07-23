#include "util.h"

static const char k_log_file_name[] = "/tmp/adium-gpg-log";

void _log_write(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    char *buf = 0;
    int size = vasprintf(&buf, format, ap);
    va_end(ap);
    if (!buf) return;
    FILE *f = fopen(k_log_file_name, "a");
    fwrite(buf, 1, size, f);
    fclose(f);
    free(buf);
}

gchar *jid_strip(const char *jid) {
    gchar *ret = 0;
    const char *p = strchr(jid, '/');
    if (p) {
        ret = g_strndup(jid, p-jid);
    } else {
        ret = g_strdup(jid);
    }
    return ret;
}
