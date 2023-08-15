#ifndef UTIL_HEADER
#define UTIL_HEADER

#define GETIPSTRING(ip, x)   ip_string(ip, x, sizeof(x))

char * ip_string(in_addr_t nip, char * string, int len);

char * domain_trim_short(char * wdomain, char *sdomain);
int split (const char *b, char *av[], int m);

unsigned long clock_get_millisecs (void);


#endif

