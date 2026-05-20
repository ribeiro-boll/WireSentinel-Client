#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "time.h"

void get_time(char *tempo, size_t size) {
    time_t timer;
    time(&timer);
    struct tm *tm_info = localtime(&timer);
    strftime(tempo, size, "%Y-%m-%dT%H:%M:%S", tm_info);
}
int extract_status_code(char* response) {
    char* tst = strdup(response);
    char *tk = strtok(tst, " ");
    tk = strtok(NULL, "\n");
    int code = atoi(tk);
    free(tst);
    return code;
}
void extract_uuid(char* response, char** uuid) {
    char* tst = strdup(response);
    //printf("\n\n\n\n%s\n\n%s\n\n\n\n", response, tst);
    char *sep = strstr(tst, "\r\n\r\n");
    *uuid = strdup(sep+4);
    free(tst);
}
/*

HTTP/1.1 200
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: SAMEORIGIN
Content-Type: text/plain;charset=UTF-8
Content-Length: 36
Date: Thu, 14 May 2026 21:57:31 GMT

fecef435-18c7-487b-bbc4-c8dacebdb957

*/