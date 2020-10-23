//
// Created by Shou C on 10/8/20.
//
//
// Citations:
// Use of pthread in TCP
// https://jameshfisher.com/2017/02/28/tcp-server-pthreads/


#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
#define error(msg) \
    printf(msg);\
    exit(0);

#define MAX_LEN_PACKET 1500

unsigned char parse_command(char* cmd, char* file_name) {
    unsigned char last_stmt_flag = 0;
    unsigned char file_flag = 0;
    char* tmp_dir = "> /tmp/output";
    int fi = 0;
    for (int i = 0; i < MAX_LEN_PACKET; ++i) {
        if (cmd[i] == '\\'){
            last_stmt_flag = 1;
            continue;
        }
        if (cmd[i] == '>'){
            file_flag = 1;
            continue;
        }
        if (file_flag){
            if (!last_stmt_flag) {
                switch (cmd[i]) {
                    case ' ':
                        continue;
                    case '<':
                    case ';':
                        break;
                }
            }
            char* nf = file_name + fi;
            *nf = cmd[i];
            fi++;
        }
        last_stmt_flag = 0;
    }
    if (file_flag == 0) {
        strcat(cmd, tmp_dir);
    } else {
        char* nf = file_name + fi;
        *nf = '\0';
    }
    return file_flag;
}

struct t_info{
    struct sockaddr_in addr;
    int new_sock_fd;
};

//#define DEBUG


void* handle_req(void* arg){
#ifdef DEBUG
    printf("arg at address %p", arg);
#endif
    struct t_info* info=(struct t_info*)arg;
#ifdef DEBUG
    printf("parents say %hu with fd %d\n", ntohs(info->addr.sin_port), info->new_sock_fd);
#endif
    char command[MAX_LEN_PACKET] = {0};
    if (read(info->new_sock_fd, command, sizeof(command)) == -1){
        printf("Failed to receive instructions from the client\n");
        return NULL;
    }
#ifdef DEBUG
    printf("got sth from %hu with fd: %d\n", ntohs(info->addr.sin_port),  info->new_sock_fd);
#endif
    system(command);
    int init_size = 16;
    char *send_buff = realloc(NULL, sizeof(char) * init_size);
    int c;
    int cter = 0;
    FILE *file;

    char file_name[MAX_LEN_PACKET] = {0};
    parse_command(command, file_name);
    file = fopen(file_name, "r");
    if (file) {
        while ((c = getc(file)) != EOF){
            send_buff[cter++] = (char)c;
            if (cter == init_size)
                send_buff = realloc(send_buff, sizeof(char)*(init_size += 16));
        }
        fclose(file);
    }
    send_buff[cter++]='\0';
    if (write(info->new_sock_fd, send_buff, strlen(send_buff)) == -1){
        printf("File transmission failed.\n");
    }
    close(info->new_sock_fd);
    free(send_buff);
    free(arg);
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        error("Please specify a port number\n");
    }

    int port = atoi(argv[1]);
    if (port < 0 || port > 65535) {
        error("Invalid port number");
    }

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        error("Failed to create a socket channel\n");
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1){
        error("Failed to bind.\n");
    }

    if (listen(sock_fd, 5) == -1) {
        error("Failed to listen.\n");
    }

    while (1){
        struct sockaddr_in client_addr = {0};
        socklen_t len = sizeof(client_addr);
        int new_sock_fd = accept(sock_fd, (struct sockaddr *) &client_addr, &len);
#ifdef DEBUG
        printf("accepted %hu with socket id %d\n", ntohs(client_addr.sin_port), new_sock_fd);
#endif
        if (new_sock_fd == -1) {
            printf("Failed to receive instructions from the client.2");
            continue;
        } else {
#ifdef DEBUG
            printf("IP:%s, PORT:%d [connected]\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
#endif
        }
        pthread_t tid;
        struct t_info* arg__ = malloc(sizeof(struct t_info));
        arg__->new_sock_fd = new_sock_fd;
        arg__->addr = client_addr;
#ifdef DEBUG
        printf("parent writes %hu -> fd %d\n",ntohs(client_addr.sin_port), arg__->new_sock_fd);
#endif
        pthread_create(&tid,NULL,handle_req,(void*)(arg__));
    }

    close(sock_fd);
}

#pragma clang diagnostic pop