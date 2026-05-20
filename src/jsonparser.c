#include "jsonparser.h"
#include "packet_list.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "misc.h"
#include "security.h"
#include "services_table.h"






void generate_json_payload(PacketList *original_inicio, char *buffer[]) {
    PacketList *inicio = original_inicio;
    char temporary_buffer[2048];
    char buffer_aplicacao[256];
    memset(*buffer, 0, MAX_JSON_SIZE);
    memset(buffer_aplicacao, 0, 256);
    strcat(*buffer, 
            "{\n"
            "  \"packets\": [\n");
    while (inicio!=NULL){
        FullInternetPacket *pkt = (inicio)->packet;
        memset(temporary_buffer, 0, 2048);
        snprintf(temporary_buffer, 2048,
            "    {\n"
            "      \"timestamp\": \"%s\",\n"
            "      \"macAdressOrigem\": \"%s\",\n"
            "      \"macAdressDestino\": \"%s\",\n"
            "      \"protocoloIp\": \"%s\",\n"
            "      \"ipOrigem\": \"%s\",\n"
            "      \"ipDestino\": \"%s\",\n"
            "      \"tempoDeVida\": %d, \n"
            "      \"tamanhoTotalHeader\": %d,\n"
            "      \"tamanhoTotalPacote\": %ld,\n"
            "      \"portaOrigem\": %d,\n"
            "      \"portaDestino\": %d,\n"
            "      \"tcpSeq\": %ld,\n"
            "      \"tcpAckSeq\": %ld,\n",
    
            // camada física
            pkt->timestamp,
            pkt->mac_origem,
            pkt->mac_destino,
            pkt->protocolo_ip,
    
            // camada IP
            pkt->ip_origem,
            pkt->ip_destino,
            pkt->tempo_vida,
            pkt->total_header_lenght,
            pkt->tamanho_total_packet,
    
            // transporte
            pkt->porta_origem,
            pkt->porta_destino,
            pkt->tcp_seq,
            pkt->tcp_ack_seq
        );    
        (pkt->tcp_ack)? strcat(temporary_buffer, "      \"tcpAck\": true,\n") : strcat(temporary_buffer, "      \"tcpAck\": false,\n" );
        (pkt->tcp_fin)? strcat(temporary_buffer, "      \"tcpFin\": true,\n") : strcat(temporary_buffer, "      \"tcpFin\": false,\n" );
        (pkt->tcp_syn)? strcat(temporary_buffer, "      \"tcpSyn\": true,\n") : strcat(temporary_buffer, "      \"tcpSyn\": false,\n" );
        (pkt->tcp_rst)? strcat(temporary_buffer, "      \"tcpRst\": true,\n") : strcat(temporary_buffer, "      \"tcpRst\": false,\n" );
        (pkt->tcp_psh)? strcat(temporary_buffer, "      \"tcpPsh\": true,\n") : strcat(temporary_buffer, "      \"tcpPsh\": false,\n" );
        (pkt->tcp_urg)? strcat(temporary_buffer, "      \"tcpUrg\": true,\n") : strcat(temporary_buffer, "      \"tcpUrg\": false,\n" );
        (pkt->tcp_cwr)? strcat(temporary_buffer, "      \"tcpCwr\": true,\n") : strcat(temporary_buffer, "      \"tcpCwr\": false,\n" );
        (pkt->tcp_ece)? strcat(temporary_buffer, "      \"tcpEce\": true,\n") : strcat(temporary_buffer, "      \"tcpEce\": false,\n" );
        (pkt->is_vlan)? strcat(temporary_buffer, "      \"isVlan\": true,\n") : strcat(temporary_buffer, "      \"isVlan\": false,\n" );
        switch (pkt->protocolo_transporte)//
        {
        case 1:
            strcat(temporary_buffer, "      \"protocolo_transporte\": \"ICMP\"\n");
            break;
        case 5:
            strcat(temporary_buffer, "      \"protocolo_transporte\": \"STREAM\"\n");
            break;
        case 6:
            strcat(temporary_buffer, "      \"protocolo_transporte\": \"TCP\",\n");
            memset(buffer_aplicacao, 0, 256);
            if (pkt->porta_destino > 0 && app_tcp_services[pkt->porta_destino]!= NULL){
                snprintf(buffer_aplicacao,256,"      \"protocolo_aplicacao\": \"%s\"\n",app_tcp_services[pkt->porta_destino]);    
                strcat(temporary_buffer, buffer_aplicacao);
            }
            else if (pkt->porta_origem > 0 && app_tcp_services[pkt->porta_origem]!= NULL){
                snprintf(buffer_aplicacao,256,"      \"protocolo_aplicacao\": \"%s\"\n",app_tcp_services[pkt->porta_origem]);    
                strcat(temporary_buffer, buffer_aplicacao);
            }
            else{
                strcat(temporary_buffer, "      \"protocolo_aplicacao\": \"Unknown/None\"\n");    
            }
            break;    
        case 17:
            strcat(temporary_buffer, "      \"protocolo_transporte\": \"UDP\",\n");
            memset(buffer_aplicacao, 0, 256);
            if (pkt->porta_destino > 0 && app_udp_services[pkt->porta_destino]!= NULL){
                snprintf(buffer_aplicacao,256,"      \"protocolo_aplicacao\": \"%s\"\n",app_udp_services[pkt->porta_destino]);    
                strcat(temporary_buffer, buffer_aplicacao);
            }
            
            else if (pkt->porta_origem > 0 && app_udp_services[pkt->porta_origem]!= NULL){
                snprintf(buffer_aplicacao,256,"      \"protocolo_aplicacao\": \"%s\"\n",app_udp_services[pkt->porta_origem]);    
                strcat(temporary_buffer, buffer_aplicacao);
            }
            else{
                strcat(temporary_buffer, "      \"protocolo_aplicacao\": \"Unknown/None\"\n");    
            }
            break;
        
        case 58:
            strcat(temporary_buffer, "      \"protocolo_transporte\": \"ICMPv6\"\n");
            break;

        default:
            strcat(temporary_buffer, "      \"protocolo_transporte\": \"Unknown/None\"\n");
            break;
        }                
        strcat(temporary_buffer, "    }");
        inicio = (inicio)->next;
        if (inicio != NULL){
            strcat(temporary_buffer, ",\n");
        }
        strcat(*buffer, temporary_buffer);
    }
    strcat(*buffer, 
            "\n  ]\n"
            "}\n");
        
}
void generate_json_header(char* host, const unsigned long int content_length, char* buffer[], char* uuid){
    char time[30], *key;
    get_time(time, 30);
    get_file_key(&key);
    char json[512];
    unsigned char digest[HMAC_SHA256_SIZE];
    unsigned int digest_len = 0;
    snprintf(json, 512, "{\r\n  X-WireSentinel-Timestamp: %s,\r\n  Length: %ld\r\n}", time, content_length);
    HMAC(EVP_sha256(), key, (int)strlen(key), (const unsigned char *) json, (int)strlen(json), digest,&digest_len);
    char digest_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&digest_hex[i * 2], "%02x", digest[i]);
    }
    digest_hex[64] = '\0';
    snprintf(*buffer, 2048,
        "POST /api/ingest HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %ld\r\n"
        "X-WireSentinel-Timestamp: %s\r\n"
        "X-WireSentinel-Credential: %s\r\n"
        "X-WireSentinel-UUID: %s\r\n"
        "User-Agent: WireSentinel-Agent/1.0\r\n\r\n",
        host, content_length, time, digest_hex, uuid
    );
    //printf("Generated JSON:\n%s\nGenerated HMAC: %s\nKey: %s\n", *buffer, digest_hex, key);
    free(key);
}
void generate_request(char* host, char* json_payload, char* buffer[], char* uuid){
    char *header = malloc(sizeof(char)*2048);
    generate_json_header(host, strlen(json_payload), &header, uuid);
    snprintf(*buffer, MAX_JSON_SIZE, "%s%s", header, json_payload);
    free(header);
}