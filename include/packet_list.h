#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef PACKET_H
#define PACKET_H
#define MAX_SIZE 64

/**
 *
 */
typedef struct{
    unsigned char is_vlan;
    unsigned char tcp_cwr;
    unsigned char tcp_ece;
    unsigned char tcp_ack;
    unsigned char tcp_fin;
    unsigned char tcp_syn;
    unsigned char tcp_rst;
    unsigned char tcp_psh;
    unsigned char tcp_urg;
    //camada Fisica
    char mac_origem[MAX_SIZE];
    char mac_destino[MAX_SIZE];
    char protocolo_ip[MAX_SIZE]; // ipv4 | ipv6 | arp 

    //camada IP
    char ip_origem[MAX_SIZE];
    char ip_destino[MAX_SIZE];
    int tempo_vida; // tempo de vida restante do packet, basicamente pra ver quantos roteadores que o pacote passou
    int total_header_lenght; // ip->ihl*4
    long int tamanho_total_packet;      // recv - total_header_len
    //camada de Transferencia
    int porta_origem;
    int porta_destino;
    long int tcp_seq; //TCP Apenas
    long int tcp_ack_seq; //TCP Apenas
    // TCP flags (sim,  apenas TCP)
    int protocolo_transporte; 
    /* 
        armazena o numero do protocolo, pra depois 
        no json builder, ele ser parseado
    */

    // metadado
    char timestamp[30]; //formato aceito pelo LocalTime
} FullInternetPacket;


typedef struct PacketList{
    FullInternetPacket *packet;
    struct PacketList *next;
} PacketList;

void insert_packet_node_on_list(PacketList **inicio, PacketList **final, FullInternetPacket **pkt, int *packet_nmbr);
void free_list(PacketList **inicio, int *packet_nmbr);
void free_packet(PacketList **inicio, int *itens_quantity) ;
#endif