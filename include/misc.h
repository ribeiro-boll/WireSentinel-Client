#ifndef MISC_H
#define MISC_H
void get_time(char *tempo, size_t size);
int extract_status_code(char* response);
void extract_uuid(char* buffer, char**uuid);
#endif