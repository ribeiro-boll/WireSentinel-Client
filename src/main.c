#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <openssl/hmac.h>
#include "buffer_list.h"
#include "misc.h"
#include "packet_service.h"
#include "packet_list.h"
#include "security.h"
#include "jsonparser.h"

#define MAX_ITENS 400
#define MAX_SIZE 64

pthread_mutex_t mutex_processing;
pthread_mutex_t mutex_payload;

pthread_cond_t cond_processing;
pthread_cond_t cond_payload;
int test = 0;
int nmbr_itens = 0;
int nmbr_packets = 0;
int cond_payload_ready =0;
char tempo[MAX_SIZE];
char *UUID;
#include <signal.h>

Buffer_List *inicio_buffer = NULL;
Buffer_List *final_buffer = NULL;

PacketList *inicio_packet = NULL;
PacketList *final_packet = NULL;



static ssize_t send_all(int socketfd, const char *buffer, size_t length) {
    size_t sent_total = 0;

    while (sent_total < length) {
        ssize_t sent = send(socketfd, buffer + sent_total, length - sent_total, 0);
        if (sent <= 0) {
            return -1;
        }
        sent_total += (size_t) sent;
    }

    return (ssize_t) sent_total;
}

static ssize_t recv_http_response(int socketfd, char *buffer, size_t buffer_size) {
    if (buffer == NULL || buffer_size == 0) return -1;
    ssize_t len = recv(socketfd, buffer, buffer_size - 1, 0);
    if (len <= 0) {
        buffer[0] = '\0';
        return len;
    }
    buffer[len] = '\0';
    return len;
}


void start_server(int * socketfd, struct addrinfo *socketConfig, struct addrinfo ** socketList, char *address, char *port) {
    memset(socketConfig, 0, sizeof(*socketConfig));
    socketConfig->ai_family = AF_INET;
    socketConfig->ai_socktype = SOCK_STREAM;
    socketConfig->ai_flags = AI_PASSIVE;
    char time[MAX_SIZE];
    getaddrinfo(address, port, socketConfig, socketList);
    *socketfd   = socket((*socketList)->ai_family,(*socketList)->ai_socktype,(*socketList)->ai_protocol);

    while (connect(*socketfd, (*socketList)->ai_addr, (*socketList)->ai_addrlen) != 0){
        *socketfd = socket((*socketList)->ai_family,(*socketList)->ai_socktype,(*socketList)->ai_protocol);
        get_time(time, MAX_SIZE);
        printf("[%s] Falha ao conectar com o servidor (> %s:%s <), tentando novamente em 5 segundos...\n",time, address, port);
        sleep(5);
    }
    get_time(time, MAX_SIZE);
}
void case_not_ok( char* addr, char* prt, char* key, int socketfd_server, int* code, char** uuid) {
    char buffer[2048], time[30];
    char json[512];
    unsigned char digest[HMAC_SHA256_SIZE];
    unsigned int digest_len = 0;
    get_time(time, 30);
    snprintf(json, 512, "{\r\n  X-WireSentinel-Timestamp: %s,\r\n  User-Agent: %s\r\n}", time, "WireSentinel-Agent/1.0");
    HMAC(EVP_sha256(), key, (int)strlen(key), (const unsigned char *) json, (int)strlen(json), digest,&digest_len);
    char digest_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&digest_hex[i * 2], "%02x", digest[i]);
    }
    digest_hex[64] = '\0';
    snprintf(buffer, 2048,
        "GET /api/register HTTP/1.1\r\n"
        "Host: %s:%s\r\n"
        "X-WireSentinel-Timestamp: %s\r\n"
        "X-WireSentinel-Credential: %s\r\n"
        "Connection: close\r\n"
        "User-Agent: WireSentinel-Agent/1.0\r\n\r\n",
        addr, prt, time, digest_hex
    );
    ssize_t len = send_all(socketfd_server, buffer, strlen(buffer));
    if (len<0) {
        printf("[%s] Erro! falha ao enviar a requisição a chave UUID do servidor... verifique se está tudo certo com o servidor e tente novamente...\n", time);
        exit(1);
    }
    char http_response_buffer[4096];
    ssize_t recv_len = recv_http_response(socketfd_server, http_response_buffer, sizeof(http_response_buffer));
    if (recv_len <= 0) {
        printf("[%s] Erro! servidor nao respondeu ao registro do UUID.\n", time);
        exit(1);
    }
    *code = extract_status_code(http_response_buffer);
    if (*code != 200) {
        printf("algo de errado, codigo de resposta http: %d", *code);
        exit(1);
    }
    extract_uuid(http_response_buffer, uuid);
    if (*uuid == NULL) {
        printf("[%s] Erro! resposta do servidor nao contem UUID valido.\n", time);
        exit(1);
    }
    printf("[%s] New UUID: (> %s <)\n", time, *uuid);
    set_UUID(*uuid);
}

void *routine_processing(void*arg) {
    (void) arg;
    long int secs = time(NULL);
    long int currsecs;
    while (1){
        currsecs = time(NULL);
        pthread_mutex_lock(&mutex_processing);
        while (nmbr_itens == 0) {
            pthread_cond_wait(&cond_processing,&mutex_processing);
        }
        Buffer_List *temp = inicio_buffer;
        inicio_buffer = inicio_buffer->next;
        FullInternetPacket *node = fill_fullPacket_node(temp->content,temp->recvlen);
        if (node == NULL) {
            free_item(&temp, &nmbr_itens);
            pthread_mutex_unlock(&mutex_processing);
        }
        else if (strcmp(node->mac_destino, "00:00:00:00:00:00") == 0 || strcmp(node->mac_origem, "00:00:00:00:00:00") == 0) {
            free(node);
            free_item(&temp, &nmbr_itens);
            pthread_mutex_unlock(&mutex_processing);
        }
        else {
            node->tamanho_total_packet = temp->recvlen;
            insert_packet_node_on_list(&inicio_packet,&final_packet, &node,&nmbr_packets);
            free_item(&temp, &nmbr_itens);
            test ++;
            pthread_mutex_unlock(&mutex_processing);
        }
        if (test >= 2000 || (currsecs - secs) >= 5 ) {
            pthread_mutex_lock(&mutex_processing);
            cond_payload_ready =1;
            test = 0;
            secs = time(NULL);
            pthread_mutex_unlock(&mutex_processing);
            pthread_cond_signal(&cond_payload);
        }
    }
}

void *routine_payload(void*arg) {
    (void) arg;
    char *addr, *prt, urlbuffer[2048];
    get_file_url(&addr);
    get_file_prt(&prt);
    snprintf(urlbuffer, 2048, "%s:%s", addr, prt);

    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    struct addrinfo socketConfig;
    struct addrinfo *socketList;
    int socketfd_server;
    start_server(&socketfd_server, &socketConfig, &socketList, addr, prt);
    setsockopt(socketfd_server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    char time[30], *key;
    get_time(time, 30);
    get_file_key(&key);
    char json[512];
    unsigned char digest[HMAC_SHA256_SIZE];
    unsigned int digest_len = 0;
    snprintf(json, 512, "{\r\n  X-WireSentinel-Timestamp: %s,\r\n  User-Agent: %s\r\n}", time, "WireSentinel-Agent/1.0");
    HMAC(EVP_sha256(), key, (int)strlen(key), (const unsigned char *) json, (int)strlen(json), digest,&digest_len);
    char digest_hex[65], *uuid = NULL;
    int code;
    for (int i = 0; i < 32; i++) {
        sprintf(&digest_hex[i * 2], "%02x", digest[i]);
    }
    digest_hex[64] = '\0';
    if (check_if_UUID_exists()) {
        get_UUID(&uuid);
        char buffer[2048];
        snprintf(buffer, 2048,
            "GET /api/client_auth HTTP/1.1\r\n"
            "Host: %s:%s\r\n"
            "X-WireSentinel-Timestamp: %s\r\n"
            "X-WireSentinel-Credential: %s\r\n"
            "X-WireSentinel-UUID: %s\r\n"
            "Connection: close\r\n"
            "User-Agent: WireSentinel-Agent/1.0\r\n\r\n",
            addr, prt, time, digest_hex, uuid
        );
        close(socketfd_server);
        start_server(&socketfd_server, &socketConfig, &socketList, addr, prt);
        setsockopt(socketfd_server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        ssize_t len = send_all(socketfd_server, buffer, strlen(buffer));
        if (len<0) {
            printf("[%s] Erro! falha ao enviar a requisição a chave UUID do servidor... verifique se está tudo certo com o servidor e tente novamente...\n", time);
            exit(1);
        }
        char http_response_buffer[4096];
        ssize_t recv_len = recv_http_response(socketfd_server, http_response_buffer, sizeof(http_response_buffer));
        if (recv_len <= 0) {
            code = -1;
        } else {
            code = extract_status_code(http_response_buffer);
        }
        if (code == 200) {
            get_UUID(&uuid);
        }
        else {
            close(socketfd_server);
            start_server(&socketfd_server, &socketConfig, &socketList, addr, prt);
            setsockopt(socketfd_server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            case_not_ok(addr, prt, key, socketfd_server, &code, &uuid);
            get_time(time, 30);
        }
        free(key);
    }
    else {
        case_not_ok(addr, prt, key, socketfd_server, &code, &uuid);
        free(key);
    }
    char recv_buffer[4096];
    int local_count;
    while (1){
        pthread_mutex_lock(&mutex_processing);
        while (inicio_packet==NULL || !cond_payload_ready) {
            pthread_cond_wait(&cond_payload,&mutex_processing);
        }
        char *json_payload = malloc(sizeof(char) * MAX_JSON_SIZE);
        char *json_request = malloc(sizeof(char) * MAX_JSON_SIZE);
        PacketList *local_copy = inicio_packet;
        local_count = nmbr_packets;
        inicio_packet = NULL;
        final_packet = NULL;
        nmbr_packets = 0;
        pthread_mutex_unlock(&mutex_processing);
        generate_json_payload(local_copy, &json_payload);
        generate_request(urlbuffer, json_payload, &json_request, uuid);
        close(socketfd_server);
        start_server(&socketfd_server, &socketConfig, &socketList, addr, prt);
        setsockopt(socketfd_server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        ssize_t result = send_all(socketfd_server, json_request, strlen(json_request));
        free_list(&local_copy, &local_count);
        while (result == -1) {
            close(socketfd_server);
            start_server(&socketfd_server, &socketConfig, &socketList, addr, prt);
            setsockopt(socketfd_server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            result = send_all(socketfd_server, json_request, strlen(json_request));
        }
        result = recv_http_response(socketfd_server, recv_buffer, sizeof(recv_buffer));
        while (result <= 0) {
            close(socketfd_server);
            start_server(&socketfd_server, &socketConfig, &socketList, addr, prt);
            setsockopt(socketfd_server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            result = send_all(socketfd_server, json_request, strlen(json_request));
            if (result == -1) continue;
            result = recv_http_response(socketfd_server, recv_buffer, sizeof(recv_buffer));
        }
        if (extract_status_code(recv_buffer) != 200) {
            char *key = NULL;
            get_file_key(&key);
            close(socketfd_server);
            start_server(&socketfd_server, &socketConfig, &socketList, addr, prt);
            setsockopt(socketfd_server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            case_not_ok(addr, prt,  key, socketfd_server, &code, &uuid);
            free(key);
        }
        get_time(time, MAX_SIZE);
        printf("[%s] Envio da requisicao ao servidor completo! Aguardando proximo payload...\n",time);
        cond_payload_ready =0;
        free(json_payload);
        free(json_request);
    }
}

int main() {
    unsigned char buffer[65535];
    signal(SIGPIPE, SIG_IGN);
    pthread_mutex_init(&mutex_processing, NULL);
    pthread_cond_init(&cond_processing, NULL);

    pthread_mutex_init(&mutex_payload, NULL);
    pthread_cond_init(&cond_payload, NULL);

    file_greeter();

    pthread_t processing, payload;
    pthread_create(&processing, NULL, routine_processing,NULL);
    pthread_create(&payload, NULL, routine_payload,NULL);
    int socketfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if (socketfd < 0) {
        perror("socket");
        return 1;
    }
    long int bytes_recived;
    while(1){
        bytes_recived = recvfrom(socketfd, buffer, sizeof(buffer), 0,NULL,NULL);
        if (bytes_recived>0) {
            pthread_mutex_lock(&mutex_processing);
            add_item(&nmbr_itens,buffer,&inicio_buffer, &final_buffer,bytes_recived);
            pthread_mutex_unlock(&mutex_processing);
            pthread_cond_signal(&cond_processing);

        }
    }
}
