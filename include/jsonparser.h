#ifndef JSONPARSER_H
#define JSONPARSER_H
#include "packet_list.h"
#define MAX_JSON_SIZE (long)(1024*1024*3)
#define HMAC_SHA256_SIZE 32
    void generate_json_payload(PacketList *original_inicio, char *buffer[]);
    void generate_json_header(char* host, unsigned long int content_length, char* buffer[], char* uuid);
    void generate_request(char* host, char* json_payload, char* buffer[], char* uuid);
#endif