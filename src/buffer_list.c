//
// Created by bolota on 08/05/2026.
//

#include "buffer_list.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/core.h>


void free_item(Buffer_List **inicio, int *itens_quantity) {
    if (*inicio != NULL) {
        Buffer_List *temp = (*inicio);
        *inicio = (*inicio)->next;
        (*itens_quantity)--;
        free(temp);
    }
    else {
        *inicio = NULL;
    }
}

void add_item(int *itens_quantity, unsigned char buffer[], Buffer_List **inicio, Buffer_List **final, long int recv_bytes) {
    Buffer_List *new_item_list = malloc(sizeof(Buffer_List));
    memcpy(new_item_list->content, buffer, recv_bytes);
    new_item_list->recvlen = recv_bytes;
    new_item_list->next = NULL;
    if (*inicio == NULL) {
        *inicio = new_item_list;
        *final = new_item_list;
    }
    else {
        while (*itens_quantity >= 1000) {
            free_item(inicio, itens_quantity);
        }
        (*final)->next = new_item_list;
        *final = new_item_list;
    }
    (*itens_quantity)++;
}
