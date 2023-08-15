#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <glib.h>
#include "common.h"

char* gstr_set_string(utf8_string * ustr, char *uval){
	int len;
	if(ustr->str){
		free(ustr->str);
		ustr->str = NULL;
		ustr->len = 0;
	}
	if(uval == NULL) return NULL;
	
	len = strlen(uval);

	//convert to utf8 string
	ustr->str = malloc(len+1);
	
	
	if(!ustr->str) {
		printf("malloc failed for lenth %d\n", len);
		return NULL;
	}
	memcpy(ustr->str, uval, len);
	ustr->str[len] = 0;
	
	ustr->len = len;

	return ustr->str;
}

