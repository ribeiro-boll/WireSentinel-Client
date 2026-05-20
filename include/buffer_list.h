//
// Created by bolota on 08/05/2026.
//

#ifndef WIRESENTINEL_CLIENT_BUFFER_LIST_H
#define WIRESENTINEL_CLIENT_BUFFER_LIST_H
#define MAX_BUFFER_ITENS 1000
typedef struct node{
    unsigned char content[65535];
    long int recvlen;
    struct node *next;
}Buffer_List;
void add_item(int *itens_quantity, unsigned char buffer[], Buffer_List **inicio, Buffer_List **final, long int recv_itens) ;
void free_item(Buffer_List **inicio, int *itens_quantity);
#endif //WIRESENTINEL_CLIENT_BUFFER_LIST_H
