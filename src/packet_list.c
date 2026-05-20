#include <stdio.h>
#include <stdlib.h>
#include "packet_list.h"

void free_packet(PacketList **inicio, int *itens_quantity) {
    if (*inicio != NULL) {
        PacketList *temp = (*inicio);
        *inicio = (*inicio)->next;
        (*itens_quantity)--;
        free(temp->packet);
        free(temp);
    }
    else {
        *inicio = NULL;
    }
}
void insert_packet_node_on_list(PacketList **inicio, PacketList **final, FullInternetPacket **pkt, int *packet_nmbr){
    PacketList *new_node = malloc(sizeof(PacketList));
    new_node->packet = *pkt;
    new_node->next = NULL;
    if (*inicio == NULL){
        *inicio = new_node;
        *final = new_node;
        (*packet_nmbr)++;
    }
    else{
        while (*packet_nmbr >= 1000) {
            free_packet(inicio, packet_nmbr);
        }
        (*final)->next = new_node;
        *final = new_node; 
        (*packet_nmbr)++;
    }
}

void free_list(PacketList **inicio, int *packet_nmbr){
    while (*inicio!=NULL){
        PacketList *temp = *inicio;
        *inicio = (*inicio)->next;
        free(temp->packet);
        free(temp);
    }
    *packet_nmbr = 0;
}

