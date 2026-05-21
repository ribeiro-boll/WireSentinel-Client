#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define PATH "" // modeloa = "exmpl/src/sec/"

static char *dup_config_value(const char *line) {
    if (line == NULL) return strdup("");

    const char *value = strchr(line, '=');
    value = (value != NULL) ? value + 1 : line;

    size_t len = strcspn(value, "\r\n");
    char *out = malloc(len + 1);
    if (out == NULL) return NULL;

    memcpy(out, value, len);
    out[len] = '\0';
    return out;
}

void get_file_path(char** path_og){
    *path_og = malloc(sizeof(char) * 256);
    if (*path_og == NULL) return;

    if(strcmp(PATH, "") == 0) {
        snprintf(*path_og, 256, ".security");
    }
    else {
        snprintf(*path_og, 256, "%s.security", PATH);
    }
}

void get_file_path_uuid(char** path_og){
    *path_og = malloc(sizeof(char) * 256);
    if (*path_og == NULL) return;

    if(strcmp(PATH, "") == 0) {
        snprintf(*path_og, 256, ".uuid");
    }
    else {
        snprintf(*path_og, 256, "%s.uuid", PATH);
    }
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
    char* path = NULL;
    get_file_path(&path);
    if (path == NULL) return 4;

    FILE *fl = fopen(path,"w");
    free(path);
    if (fl == NULL) return 4;

    snprintf(buffer, 2048,
        "SHRD_SCRT=%s\n"
        "URL=%s\n"
        "PORT=%s\n",
        key, url, port);
    fputs(buffer, fl);
    fclose(fl);
    return 0;
}

int confirm_if_file_exists(){
    char* path = NULL;
    get_file_path(&path);
    if (path == NULL) return 0;

    FILE *fl = fopen(path,"r");
    free(path);
    if (fl == NULL){
        return 0;
    }
    fclose(fl);
    return 1;
}

void get_file_full(char **fullFile, int line_nmbr){
    if (fullFile == NULL) return;
    *fullFile = NULL;

    char buffer[2048] = "";
    char* path = NULL;
    get_file_path(&path);
    if (path == NULL) return;

    FILE *fl = fopen(path,"r");
    free(path);
    if (fl == NULL) return;

    for(int i = 0; i <= line_nmbr; i++) {
        if (fgets(buffer, sizeof(buffer), fl) == NULL) {
            fclose(fl);
            *fullFile = strdup("");
            return;
        }
        if(buffer[0] == '\n'){
            i--;
        }
    }

    fclose(fl);
    *fullFile = strdup(buffer);
}

void get_file_key(char **shared_key){
    char *line = NULL;
    get_file_full(&line, 0);
    *shared_key = dup_config_value(line);
    free(line);
}

void get_file_url(char **url){
    char *line = NULL;
    get_file_full(&line, 1);
    *url = dup_config_value(line);
    free(line);
}

void get_file_prt(char** port){
    char *line = NULL;
    get_file_full(&line, 2);
    *port = dup_config_value(line);
    free(line);
}

int file_greeter(){
    char *key = NULL, *url = NULL, *port = NULL, awsr;
    char key_stack[256], url_stack[80], port_stack[10];
    int cond_break_loop;

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

        free(key);
        free(url);
        free(port);
    }
    else{
        cond_break_loop = 1;
    }

    while (cond_break_loop){
        printf("Digite a Chave Compartilhada (lenght < 256)\n-> ");
        fgets(key_stack, 255, stdin);
        key_stack[strcspn(key_stack, "\n")] = '\0';
        printf("Digite a URL\n-> ");
        fgets(url_stack, 79, stdin);
        url_stack[strcspn(url_stack, "\n")] = '\0';
        printf("Digite a Porta\n-> ");
        fgets(port_stack, 9, stdin);
        port_stack[strcspn(port_stack, "\n")] = '\0';

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
        default:
            printf("\nErro: nao foi possivel criar o arquivo de configuracao...\n\n ");
            break;
        }
    }
    return 0;
}

int check_if_UUID_exists() {
    char* path = NULL;
    get_file_path_uuid(&path);
    if (path == NULL) return 0;

    FILE *fl = fopen(path,"r");
    free(path);
    if (fl == NULL){
        return 0;
    }
    fclose(fl);
    return 1;
}

void get_UUID(char** uuid) {
    if (uuid == NULL) return;
    *uuid = NULL;

    if (check_if_UUID_exists()) {
        char buffer[2048] = "";
        char* path = NULL;
        get_file_path_uuid(&path);
        if (path == NULL) return;

        FILE *fl = fopen(path,"r");
        free(path);
        if (fl == NULL) return;

        if (fgets(buffer, sizeof(buffer), fl) == NULL) {
            fclose(fl);
            return;
        }
        fclose(fl);

        *uuid = dup_config_value(buffer);
    }
}

void set_UUID(char* uuid) {
    if (uuid == NULL) return;

    char buffer[2048]= "";
    snprintf(buffer, 2048, "UUID=%s\n", uuid);
    char* path = NULL;
    get_file_path_uuid(&path);
    if (path == NULL) return;

    FILE* fl = fopen(path, "w");
    free(path);
    if (fl == NULL) return;

    fputs(buffer,fl);
    fclose(fl);
}
