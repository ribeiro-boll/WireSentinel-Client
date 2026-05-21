#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include "packet_list.h"
/*
 * IEEE 802.3 Ethernet constants
 * Tamanhos do header Ethernet
 */
#define ETH_ALEN 6   // bytes de um endereço MAC
#define ETH_HLEN 14  // tamanho do header Ethernet

/*
 * Ethernet Protocol IDs (Layer 2 → Layer 3)
 * Só os que você usa no parser
 */
#define ETH_P_IP       0x0800  // IPv4
#define ETH_P_ARP      0x0806  // ARP
#define ETH_P_IPV6     0x86DD  // IPv6
#define ETH_P_RARP     0x8035  // Reverse ARP
#define ETH_P_8021Q    0x8100  // VLAN 802.1Q
#define ETH_P_MPLS_UC  0x8847  // MPLS Unicast
#define ETH_P_MPLS_MC  0x8848  // MPLS Multicast
#define ETH_P_PPP_DISC 0x8863  // PPPoE Discovery
#define ETH_P_PPP_SES  0x8864  // PPPoE Session

/*
 * Forward declaration
 * A struct real está em packet.h
 */
/*
 * Inicializa a struct com valores padrão ("Null" e 0)
 */
void init_packet(FullInternetPacket *p);

/*
 * Parsing da camada de transporte (Layer 4)
 * Retorna o tamanho do header
 */
int fill_tcp(unsigned char *buffer, int offset, FullInternetPacket* node);
int fill_udp(unsigned char *buffer, int offset, FullInternetPacket* node);

/*
 * Parsing da camada de rede (Layer 3)
 */
void fill_ipv4(unsigned char *buffer, FullInternetPacket* node,int offset_ethernet);
int fill_ipv6(unsigned char *buffer, long int recvlen, FullInternetPacket* node,int offset_ethernet);

/*
 * Função principal do parser
 * Recebe buffer bruto e retorna struct preenchida
 */
FullInternetPacket* fill_fullPacket_node(unsigned char *buffer, long int recvlen);

#endif