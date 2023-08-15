#include <string.h>
#include "common.h"


static char *
token (char **s)
{
    char   *b, *bp = *s;

    while (*bp && (*bp == ' ' || *bp == '\t' || *bp == '\n'))
        bp++;
    b = bp;

    while (*bp && *bp != ' ' && *bp != '\t' && *bp != '\n')
        bp++;
    if (*bp)
        (*bp++ = '\0');
    *s = bp;

    return (b == bp) ? (char *) 0 : b;
}

int 
split (const char *b, char *av[], int m)
{
    char   *bp = (char *)b;
    int     n = 0;

    while ((av[n] = token (&bp)) != NULL)
        if (++n >= m)
            break;
    return n;
}



/* token: return next token in string */
static char *
mtoken (char **s, char ctoken)
{
    char   *b, *bp = *s;

    while (*bp && (*bp == ctoken ))
        bp++;
    b = bp;

    while (*bp && *bp != ctoken)
        bp++;
    if (*bp)
        (*bp++ = '\0');
    *s = bp;

    return (b == bp) ? (char *) 0 : b;
}

/* split: split buffer into argument list */
int 
msplit (const char *b, char *av[], int m, char ctoken)
{
    char   *bp = (char *)b;
    int     n = 0;

    while ((av[n] = mtoken (&bp, ctoken)) != NULL)
        if (++n >= m)
            break;
    return n;
}



/* token: return next token in string */
static char *
token_words (char **s)
{
    char   *b, *bp = *s;
	char * start1= NULL;
	char * start2 = NULL;
	
    while (*bp && (*bp == ' ' || *bp == '\t' || *bp == '\n'))
        bp++;
    b = bp;

	
    while (*bp && *bp != '\n'){
		if( *bp == ' ' || *bp == '\t' ) {
			if(start1 == NULL && start2 == NULL) break;
			else {
				bp++;
				continue;
			}
		}
		if(*bp == '"' ) {
			if(start1 == NULL) start1 = bp;
			else start1 = NULL;
		}
		else if(*bp == '\'') {
			if(start2 == NULL) start2 = bp;
			else start2 = NULL;
		}
		
        bp++;
    }


	
    if (*bp)
        (*bp++ = '\0');
    *s = bp;

    return (b == bp) ? (char *) 0 : b;
}

/* split: split buffer into argument list, if some words include "/' ,means its must be whole " */
int 
split_words (const char *b, char *av[], int m)
{
    char   *bp = (char *)b;
    int     n = 0;

    while ((av[n] = token_words (&bp)) != NULL)
        if (++n >= m)
            break;
    return n;
}

