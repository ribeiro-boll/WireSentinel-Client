#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define PATH "" // modeloa = "exmpl/src/sec/" 



/*

1- senha compartilhada muito longa

2- url muito longo

3- porta muito longa

*/
void get_file_path(char** path_og){
    *path_og = malloc(sizeof(char)*100);
    if(strcmp(PATH, "") == 0) {
        strcpy(*path_og, ".security");
    }
    else {
        strcat(*path_og, ".security");
    };
}
void get_file_path_uuid(char** path_og){
    *path_og = malloc(sizeof(char)*100);
    if(strcmp(PATH, "") == 0) {
        strcpy(*path_og, ".uuid");
    }
    else {
        strcat(*path_og, ".uuid");
    };
}

int create_security_file(char* key, char* url, char* port){
    if (strlen(key)>256){
        return 1;
    }
    if (strlen(url)>80){
        return 2;
    }
    if (strlen(port)>10){
        return 3;
    }
    char buffer[2048];
    char* path;
    get_file_path(&path);
    FILE *fl = fopen(path,"w");
    
    snprintf(buffer, 2048, 
        "SHRD_SCRT=%s\n"
        "URL=%s\n"
        "PORT=%s\n",
        key, url, port);
    fputs(buffer, fl);
    //rewind(fl);
    fclose(fl);
    return 0;
}


int confirm_if_file_exists(){
    char* path;
    get_file_path(&path);
    FILE *fl = fopen(path,"r");
    if (fl == NULL){
        return 0;
    }
    rewind(fl);
    fclose(fl);
    return 1;
}
void get_file_full(char **fullFile, int line_nmbr){
    char buffer[2048] = "";
    char* path;
    get_file_path(&path);
    FILE *fl = fopen(path,"r");
    for(int i = 0; i<=(line_nmbr); i++) {
        fgets(buffer, 2047, fl);
        if(buffer[0] == '\n'){
            fgets(buffer, 2047, fl);
        }
    }
    rewind(fl);
    fclose(fl);
    *fullFile= strdup(buffer);
    free(path);
}
void get_file_key(char **shared_key){
    char *buffer = malloc(sizeof(char)*2048);
    get_file_full(&buffer, 0);
    buffer+=10;
    buffer[strlen(buffer)-1] = '\0';
    *shared_key = strdup(buffer);
    free(buffer-10);
}

void get_file_url(char **url){
    char *buffer = malloc(sizeof(char)*2048);
    get_file_full(&buffer, 1);
    buffer+=4;
    buffer[strlen(buffer)-1] = '\0';
    *url = strdup(buffer);
    free(buffer-4);
}
void get_file_prt(char** port){
    char *buffer = malloc(sizeof(char)*2048);
    get_file_full(&buffer, 2);
    buffer+=5;
    buffer[strlen(buffer)-1] = '\0';
    *port = strdup(buffer);
    free(buffer-5);
}

int file_greeter(){
    char *key, *url, *port, awsr;
    char key_stack[256], url_stack[80], port_stack[10];
    int cond_break_loop;
    char* path;
    get_file_path(&path);
    if (confirm_if_file_exists()){
        get_file_key(&key);
        get_file_url(&url);
        get_file_prt(&port);
        
        printf("Arquivo de configuracao detectado, url: [ %s:%s ]\nKey: %s\ndeseja prosseguir com o link? (S/n)\n-> ",url, port, key);
        awsr = fgetc(stdin);
        if (awsr =='n' || awsr =='N') {
            cond_break_loop = 1;
            
        }
        else{
            cond_break_loop = create_security_file(key, url, port);
            cond_break_loop = 0;
        }
        if (awsr != '\n'){
            getchar();
        }

        //free(key);
        //free(url);
        //free(port);
    }
    else{
        cond_break_loop = 1;
    }
    while (cond_break_loop){
        printf("Digite a Chave Compartilhada (lenght < 256)\n-> ");
        fgets(key_stack, 255, stdin);
        key_stack[strcspn(key_stack, "\n")] = '\0'; // Remove newline character
        printf("Digite a URL\n-> ");
        fgets(url_stack, 79, stdin);
        url_stack[strcspn(url_stack, "\n")] = '\0'; // Remove newline character
        printf("Digite a Porta\n-> ");
        fgets(port_stack, 9, stdin);
        port_stack[strcspn(port_stack, "\n")] = '\0'; // Remove newline character

        cond_break_loop = create_security_file(key_stack, url_stack, port_stack);
        if (cond_break_loop == 0) break;
        switch (cond_break_loop){
        case 1:
            printf("\nErro: Key muito longa tente novamente...\n\n ");
            break;
        case 2:
            printf("\nErro: URL muito longa tente novamente...\n\n ");
            break;
        case 3:
            printf("\nErro: Porta muito longa tente novamente...\n\n ");
            break;
        }  
    }
    return 0;
}

int check_if_UUID_exists() {
    char* path;
    get_file_path_uuid(&path);
    FILE *fl = fopen(path,"r");
    if (fl == NULL){
        return 0;
    }
    free(path);
    rewind(fl);
    fclose(fl);
    return 1;
}

// if uuid exists, returns char sequence, else returns NULL
void get_UUID(char** uuid) {
    if (check_if_UUID_exists()) {
        char *buffer = malloc(sizeof(char)*2048);
        char* path;
        get_file_path_uuid(&path);
        FILE *fl = fopen(path,"r");
        fgets(buffer,2048, fl);
        free(path);
        rewind(fl);
        fclose(fl);
        buffer[strlen(buffer)-1] = '\0';
        *uuid = strdup(buffer + 5);
        free(buffer);
    }
    else
        *uuid = NULL;
}

void set_UUID(char* uuid) {
    char buffer[2048]= "";
    snprintf(buffer, 2048, "UUID=%s\n", uuid);
    char* path;
    get_file_path_uuid(&path);
    FILE* fl = fopen(path, "w");
    fputs(buffer,fl);
    fclose(fl);
    free(path);
}
