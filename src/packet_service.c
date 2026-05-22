#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "misc.h"
#include "packet_list.h"
#include "security.h"
#include "jsonparser.h"
#include "packet_service.h"

void init_packet(FullInternetPacket *p) {
    if (!p) return;
    // camada IP
    strcpy(p->ip_origem, "Null");
    strcpy(p->ip_destino, "Null");
    p->protocolo_transporte = -1;
    p->tempo_vida = 0;
    p->total_header_lenght = 0;
    p->tamanho_total_packet = 0;

    // camada transporte
    p->porta_destino = 0;
    p->porta_origem = 0;
    p->tcp_seq = 0;
    p->tcp_ack_seq = 0;

    p->tcp_ack = 0;
    p->tcp_fin = 0;
    p->tcp_syn = 0;
    p->tcp_rst = 0;
    p->tcp_psh = 0;
    p->tcp_urg = 0;

    // metadado
}

//retorna o lenght do header
int fill_tcp(unsigned char *buffer, int offset, FullInternetPacket* node){
    int source_port = (((uint16_t)buffer[offset])<<8 | buffer[offset+1]);
    int dest_port = (((uint16_t)buffer[offset+2])<<8 | buffer[offset+3]);
    unsigned int seq_nbr = (((uint32_t)buffer[offset+4])<<24 | (uint32_t)buffer[offset+5]<<16 | (uint32_t)buffer[offset+6]<<8 | (uint32_t)buffer[offset+7]);
    unsigned ack_nbr = (((uint32_t)buffer[offset+8])<<24 | (uint32_t)buffer[offset+9]<<16 | (uint32_t)buffer[offset+10]<<8 | (uint32_t)buffer[offset+11]);
    node->porta_destino = dest_port;
    node->porta_origem = source_port;
    node->tcp_seq = (long int) seq_nbr;
    node->tcp_ack_seq = (long int) ack_nbr;

    node->tcp_fin = ((buffer[offset+13] & 0b00000001))? 1 : 0;
    node->tcp_syn = ((buffer[offset+13] & 0b00000010))? 1 : 0;
    node->tcp_rst = ((buffer[offset+13] & 0b00000100))? 1 : 0;
    node->tcp_psh = ((buffer[offset+13] & 0b00001000))? 1 : 0;
    node->tcp_ack = ((buffer[offset+13] & 0b00010000))? 1 : 0;
    node->tcp_urg = ((buffer[offset+13] & 0b00100000))? 1 : 0;
    node->tcp_ece = ((buffer[offset+13] & 0b01000000))? 1 : 0;
    node->tcp_cwr = ((buffer[offset+13] & 0b10000000))? 1 : 0;

    int lenght = ((buffer[offset+12])>>4) *4;
    return lenght;
}
//retorna o lenght do header
int fill_udp(unsigned char *buffer, int offset, FullInternetPacket* node){
    int source_port = (((uint16_t)buffer[offset])<<8 | buffer[offset+1]);
    int dest_port = (((uint16_t)buffer[offset+2])<<8 | buffer[offset+3]);
    node->porta_destino = dest_port;
    node->porta_origem = source_port;
    return 8;
}

int fill_ipv6(unsigned char *buffer, long int recvlen, FullInternetPacket* node, int offset_ethernet){
    if (recvlen < offset_ethernet + 40) return 0;
    //int payload_lenght = ((((uint16_t)buffer[offset_ethernet + 4]) << 8) | buffer[offset_ethernet+5]);
    int ttl = buffer[offset_ethernet+7];
    int protocolo = buffer[offset_ethernet+6];
    unsigned char ip_source_raw[16];
    for (int i = 0; i < 16; i++){
        ip_source_raw[i] = buffer[offset_ethernet + 8 + i];
    }
    char ip_source[64];
    snprintf(ip_source, 64, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", ip_source_raw[0],ip_source_raw[1],ip_source_raw[2],ip_source_raw[3],ip_source_raw[4],ip_source_raw[5],ip_source_raw[6],ip_source_raw[7],ip_source_raw[8],ip_source_raw[9],ip_source_raw[10],ip_source_raw[11],ip_source_raw[12],ip_source_raw[13],ip_source_raw[14],ip_source_raw[15]);
    strcpy(node->ip_origem, ip_source);
    unsigned char ip_dest_raw[16];
    for (int i = 0; i < 16; i++){
        ip_dest_raw[i] = buffer[offset_ethernet + 24 + i];
    }
    char ip_dest[64];
    snprintf(ip_dest, 64, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", ip_dest_raw[0],ip_dest_raw[1],ip_dest_raw[2],ip_dest_raw[3],ip_dest_raw[4],ip_dest_raw[5],ip_dest_raw[6],ip_dest_raw[7],ip_dest_raw[8],ip_dest_raw[9],ip_dest_raw[10],ip_dest_raw[11],ip_dest_raw[12],ip_dest_raw[13],ip_dest_raw[14],ip_dest_raw[15]);
    strcpy(node->ip_destino, ip_dest);
    node->total_header_lenght = offset_ethernet + 40;
    //node->tamanho_total_packet = payload_lenght;
    node->tempo_vida = ttl;
    int cond_break_loop = 1;
    int curr_index = 40 + offset_ethernet;
    while (cond_break_loop && cond_break_loop < 8){
        //printf("%d  %d\n",protocolo, curr_index);
        if (curr_index < 0 || curr_index >= recvlen) {
            node->protocolo_transporte = -1;
            node->total_header_lenght = offset_ethernet + 40;
            return 0;
        }
        switch (protocolo){
            case 0:
                cond_break_loop++;
                if (curr_index + 1 >= recvlen) return 0;
                protocolo = buffer[curr_index];
                curr_index+=((int)buffer[curr_index + 1] + 1)*8;
                if (curr_index > recvlen) return 0;
                // hop-by-hop 
                // primeiro octeto/byte - prox header
                // segundo octeto/byte - tamanho do header
                break;
            case 1:
                cond_break_loop=0;
                node->protocolo_transporte = 1;//"ICMP";    
                break;
        
            case 5:
                cond_break_loop=0;
                node->protocolo_transporte = 5;//"STREA");
                break;
            case 6:
                cond_break_loop=0;
                node->protocolo_transporte = 6;//"TCP")
                break;
            case 17:
                cond_break_loop=0;
                node->protocolo_transporte = 17;//"UDP")
                break;
            
            case 43:
                cond_break_loop++;
                if (curr_index + 1 >= recvlen) return 0;
                protocolo = buffer[curr_index];
                curr_index+=((int)buffer[curr_index + 1] + 1)*8;
                if (curr_index > recvlen) return 0; 
                // routing options
                // primeiro octeto/byte - prox header
                // segundo octeto/byte - tamanho do header
                break;
        
            case 44:
                cond_break_loop++;
                if (curr_index >= recvlen) return 0;
                protocolo = buffer[curr_index];
                curr_index+=8;
                if (curr_index > recvlen) return 0;
                // fragment header
                // primeiro octeto/byte - prox header
                // 8 octetos/bytes - tamanho do header
                break;
        
            case 58:
                cond_break_loop=0;
                node->protocolo_transporte = 58;//"ICMPv");//não é metodo de transporte    
                break;

            case 60:
                cond_break_loop++;
                if (curr_index + 1 >= recvlen) return 0;
                protocolo = buffer[curr_index];
                curr_index+=((int)buffer[curr_index + 1] + 1)*8;
                if (curr_index > recvlen) return 0;
                // destination options
                // primeiro octeto/byte - prox header
                // segundo octeto/byte - tamanho do header
                break;

            default:
                //printf("IPv6 unknown: %d\n",protocolo);
                cond_break_loop=0;
                node->protocolo_transporte = -1;//"Unknown");
                break;
        }
        node->total_header_lenght = curr_index;
    }
    return 1;
}

void fill_ipv4(unsigned char *buffer, FullInternetPacket* node, int offset_ethernet){
    int ihl = ((int)(buffer[offset_ethernet] & 0b00001111)) * 4;
    //index = 1
    //int total_lenght = ((((uint16_t)buffer[offset_ethernet+2])<<8) | buffer[offset_ethernet+3]);
    //index = 3
    int time_to_live = buffer[offset_ethernet+8];
    /*
    TIPO DE PROTOCOLO
    01 ICMP
    06 TCP
    17 UDP
    */
    int protocolo = buffer[offset_ethernet+9];
    int ip_source_raw[4];
    // index = 11
    for (int i = 0; i < 4; i++){
        ip_source_raw[i] = buffer[offset_ethernet + 12+ i];
    }
    char ip_source[64];
    snprintf(ip_source, 64, "%d.%d.%d.%d", ip_source_raw[0],ip_source_raw[1],ip_source_raw[2],ip_source_raw[3]);
    int ip_dest_raw[4];
    // index = 15
    for (int i = 0; i < 4; i++){
        ip_dest_raw[i] = buffer[offset_ethernet + 16 + i];
    }
    char ip_dest[64];
    snprintf(ip_dest, 64, "%d.%d.%d.%d", ip_dest_raw[0],ip_dest_raw[1],ip_dest_raw[2],ip_dest_raw[3]);
    strcpy(node->ip_destino, ip_dest);
    strcpy(node->ip_origem, ip_source);
    node->total_header_lenght = ihl + offset_ethernet;
    node->tempo_vida = time_to_live;
    switch (protocolo){
        case 1:
            node->protocolo_transporte = 1;//"ICMP";
            break;
        case 5:
            node->protocolo_transporte = 5;//"STREAM");
            break;
        case 6:
            node->protocolo_transporte = 6;//"TCP")
            break;
        case 17:
            node->protocolo_transporte = 17;//"UDP")
            break;
        default:
            //printf("IPv4 unknown: %d\n",protocolo);
            node->protocolo_transporte = -1;//"Unknown");
            break;
    }
}

FullInternetPacket* fill_fullPacket_node(unsigned char *buffer, long int recvlen) {
    FullInternetPacket *packetNode = malloc(sizeof(FullInternetPacket));
    if (recvlen<14) {
        free(packetNode);
        return NULL;
    }
    packetNode->tamanho_total_packet = recvlen;
    memset(packetNode, 0, sizeof(FullInternetPacket));
    init_packet(packetNode);
    char buffer_txt[MAX_SIZE];
    
    // --------- Layer de Acesso a Rede ---------
    memset(buffer_txt, 0, MAX_SIZE);
    snprintf(buffer_txt,MAX_SIZE,"%02x:%02x:%02x:%02x:%02x:%02x",buffer[0],buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
    strncpy(packetNode->mac_destino,buffer_txt,MAX_SIZE);
    
    memset(buffer_txt, 0, MAX_SIZE);
    snprintf(buffer_txt,MAX_SIZE,"%02x:%02x:%02x:%02x:%02x:%02x",buffer[6],buffer[7], buffer[8], buffer[9], buffer[10], buffer[11]);
    strncpy(packetNode->mac_origem,buffer_txt,MAX_SIZE);
    int define_protocol;
    int ethtype = (((uint16_t)buffer[12]) << 8 | buffer[13]);
    int ethr_header_len = 14, offset = 0;
    if (ethtype == 0x88a8) {
        offset+=4;
        if (recvlen < 14 + offset) {
            free(packetNode);
            return NULL;
        }
        ethr_header_len+=4;
        ethtype = (((uint16_t)buffer[12 + offset]) << 8 | buffer[13 + offset]);
    }
    if (ethtype == 0x8100) {
        packetNode->is_vlan = 0b1;
        offset+=4;
        if (recvlen < 14 + offset) {
            free(packetNode);
            return NULL;
        }
        ethr_header_len+=4;
        ethtype = (((uint16_t)buffer[12 + offset]) << 8 | buffer[13 + offset]);
    }
    switch (ethtype) {
        case ETH_P_IP:
            strcpy(packetNode->protocolo_ip, "IPv4");
            define_protocol = 1;
            break;

        case ETH_P_IPV6:
            strcpy(packetNode->protocolo_ip, "IPv6");
            define_protocol = 2;
            break;

        case ETH_P_ARP:
            strcpy(packetNode->protocolo_ip, "ARP");
            define_protocol = 3;
            strcpy(packetNode->ip_origem, "Null");
            strcpy(packetNode->ip_destino, "Null");
            packetNode->protocolo_transporte = -1;
            packetNode->tempo_vida = 0;
            packetNode->total_header_lenght = 0;
            packetNode->tamanho_total_packet = 0;
            break;

        case ETH_P_RARP:
            strcpy(packetNode->protocolo_ip, "RARP");
            define_protocol = 4;
            strcpy(packetNode->ip_origem, "Null");
            strcpy(packetNode->ip_destino, "Null");
            packetNode->protocolo_transporte = -1;
            packetNode->tempo_vida = 0;
            packetNode->total_header_lenght = 0;
            packetNode->tamanho_total_packet = 0;
            break;
        case ETH_P_MPLS_UC:
            strcpy(packetNode->protocolo_ip, "MPLS Unicast");
            define_protocol = 6;
            strcpy(packetNode->ip_origem, "Null");
            strcpy(packetNode->ip_destino, "Null");
            packetNode->protocolo_transporte = -1;
            packetNode->tempo_vida = 0;
            packetNode->total_header_lenght = 0;
            packetNode->tamanho_total_packet = 0;
            break;

        case ETH_P_MPLS_MC:
            strcpy(packetNode->protocolo_ip, "MPLS Multicast");
            define_protocol = 7;
            strcpy(packetNode->ip_origem, "Null");
            strcpy(packetNode->ip_destino, "Null");
            packetNode->protocolo_transporte = -1;
            packetNode->tempo_vida = 0;
            packetNode->total_header_lenght = 0;
            packetNode->tamanho_total_packet = 0;

  
            break;

        case ETH_P_PPP_SES:
            strcpy(packetNode->protocolo_ip, "PPPoE Session");
            define_protocol = 8;
            strcpy(packetNode->ip_origem, "Null");
            strcpy(packetNode->ip_destino, "Null");
            packetNode->protocolo_transporte = -1;
            packetNode->tempo_vida = 0;
            packetNode->total_header_lenght = 0;
            packetNode->tamanho_total_packet = 0;
            break;

        case ETH_P_PPP_DISC:
            strcpy(packetNode->protocolo_ip, "PPPoE Discovery");
            define_protocol = 9;
            strcpy(packetNode->ip_origem, "Null");
            strcpy(packetNode->ip_destino, "Null");
            packetNode->protocolo_transporte = -1;
            packetNode->tempo_vida = 0;
            packetNode->total_header_lenght = 0;
            packetNode->tamanho_total_packet = 0;
            break;

        default:
            strcpy(packetNode->protocolo_ip, "Unknown/None");
            define_protocol = 10;
            strcpy(packetNode->ip_origem, "Null");
            strcpy(packetNode->ip_destino, "Null");
            packetNode->protocolo_transporte = -1;
            packetNode->tempo_vida = 0;
            packetNode->total_header_lenght = 0;
            packetNode->tamanho_total_packet = 0;
            break;
    }
    //---------------------------------------------------------------
    // index = 14
    // --------- layer de Internet ---------
    int transport_offset = 0;
    if (define_protocol == 1){
        if (recvlen< ethr_header_len+ 20) {
            free(packetNode);
            return NULL;
        }
        fill_ipv4(buffer, packetNode, ethr_header_len);
        if (packetNode->total_header_lenght < 20 + ethr_header_len || recvlen <  packetNode->total_header_lenght) {
            free(packetNode);
            return NULL;
        }
        transport_offset = packetNode->total_header_lenght; //ip->ihl*4
        switch (packetNode->protocolo_transporte){
            case 6:
                if (recvlen < transport_offset + 20) {
                    free(packetNode);
                    return NULL;
                }
                transport_offset += fill_tcp(buffer, transport_offset, packetNode);
                break;
            case 17:
                if (recvlen < transport_offset + 8) {
                    free(packetNode);
                    return NULL;
                }
                transport_offset += fill_udp(buffer, transport_offset, packetNode);
                break;
            default:
                packetNode->porta_destino = 0;
                packetNode->porta_origem = 0;
                packetNode->tcp_seq = 0;
                packetNode->tcp_ack_seq = 0;
                packetNode->tcp_ack = 0;
                packetNode->tcp_fin = 0;
                packetNode->tcp_syn = 0;
                packetNode->tcp_rst = 0;
                packetNode->tcp_psh = 0;
                packetNode->tcp_urg = 0;
                break;
        }
        packetNode->total_header_lenght = transport_offset;
    }   
    if (define_protocol == 2){
        if (recvlen< ethr_header_len + 40) {
            free(packetNode);
            return NULL;
        }
        if (!fill_ipv6(buffer, recvlen, packetNode, ethr_header_len)) {
            free(packetNode);
            return NULL;
        }
        transport_offset = packetNode->total_header_lenght;
        switch (packetNode->protocolo_transporte){
            case 6:
                if (recvlen < transport_offset + 20) {
                    free(packetNode);
                    return NULL;
                }
                transport_offset += fill_tcp(buffer, transport_offset, packetNode);

                break;
            case 17:
                if (recvlen < transport_offset + 8) {
                    free(packetNode);
                    return NULL;
                }
                transport_offset += fill_udp(buffer, transport_offset, packetNode);
                break;
            default:
                packetNode->porta_destino = 0;
                packetNode->porta_origem = 0;
                packetNode->tcp_seq = 0;
                packetNode->tcp_ack_seq = 0;
                packetNode->tcp_ack = 0;
                packetNode->tcp_fin = 0;
                packetNode->tcp_syn = 0;
                packetNode->tcp_rst = 0;
                packetNode->tcp_psh = 0;
                packetNode->tcp_urg = 0;
                break;
        }
        packetNode->total_header_lenght = transport_offset;
    }
    char time[64];
    get_time(time,64);
    strcpy(packetNode->timestamp,time); 
    return packetNode;
}