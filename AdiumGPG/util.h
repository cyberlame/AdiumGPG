#ifndef AdiumGPG_util_h
#define AdiumGPG_util_h

void _log_write(const char *format, ...);

#define log_write(format, ...) _log_write("%s: " format, __FUNCTION__, ##__VA_ARGS__)
//#define log_write(format, ...)

gchar *jid_strip(const char *jid);

#endif


