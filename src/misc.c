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
    if (response == NULL) return -1;

    // Esperado: HTTP/1.1 200 ...
    char *copy = strdup(response);
    if (copy == NULL) return -1;

    char *version = strtok(copy, " ");
    char *status = strtok(NULL, " \r\n");

    int code = -1;
    if (version != NULL && status != NULL) {
        code = atoi(status);
    }

    free(copy);
    return code;
}

void extract_uuid(char* response, char** uuid) {
    if (uuid == NULL) return;
    *uuid = NULL;

    if (response == NULL) return;

    char *sep = strstr(response, "\r\n\r\n");
    if (sep == NULL) return;

    char *body = sep + 4;
    size_t len = strcspn(body, "\r\n");
    if (len == 0) return;

    *uuid = malloc(len + 1);
    if (*uuid == NULL) return;

    memcpy(*uuid, body, len);
    (*uuid)[len] = '\0';
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
