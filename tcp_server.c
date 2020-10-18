//
// Created by Shou C on 10/8/20.
//

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

const unsigned int MAX_LEN_PACKET = 1500;

unsigned char parse_command(char* cmd, char* file_name) {
    unsigned char last_stmt_flag = 0;
    unsigned char file_flag = 0;
    char* tmp_dir = "> /tmp/output";
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
            strncat(file_name, &cmd[i], 1);
        }
        last_stmt_flag = 0;
    }
    if (file_flag == 0) {
        strcat(cmd, tmp_dir);
    }
    return file_flag;
}

struct t_info{
    struct sockaddr_in addr;
    int fd;
};

void* handle_req(void* arg){
    struct t_info* info=(struct s_info*)arg;

    char command[MAX_LEN_PACKET] = {0};
    char file_name[MAX_LEN_PACKET];
    if (read(info->fd, command, sizeof(command)) == -1){
        printf("Failed to receive instructions from the client.");
        return NULL;
    }
    unsigned char need_send_file = parse_command(command, file_name);
    system(command);
    if (need_send_file){
        int init_size = 16;
        char *send_buff = realloc(NULL, sizeof(char) * init_size);
        send_buff[0] = '\2'; // no file
        int c;
        int cter = 0;
        while (file_name[cter] != '\0'){
            send_buff[cter+1] = file_name[cter];
            cter++;
            if (cter+1 == init_size)
                send_buff = realloc(send_buff, sizeof(char)*(init_size += 16));
        }
        send_buff[++cter] = '\2';
        cter++;
        FILE *file;
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
        if (write(info->fd, send_buff, strlen(send_buff)) == -1){
            printf("Failed to send result to client.\n");
        }
        close(info->fd);
        free(send_buff);
    } else {
        int init_size = 16;
        char *send_buff = realloc(NULL, sizeof(char) * init_size);
        send_buff[0] = '\3'; // no file
        int c;
        int cter = 1;
        FILE *file;
        char* filename = "/tmp/output";
        file = fopen(filename, "r");
        if (file) {
            while ((c = getc(file)) != EOF){
                send_buff[cter++] = (char)c;
                if (cter == init_size)
                    send_buff = realloc(send_buff, sizeof(char)*(init_size += 16));
            }
            fclose(file);
        }
        send_buff[cter++]='\0';
        if (write(info->fd, send_buff, strlen(send_buff)) == -1){
            printf("Failed to receive instructions from the client.\n");
        }
        close(info->fd);
        free(send_buff);
    }
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        error("Please specify a port number");
    }

    int port = atoi(argv[1]);
    if (port < 0 || port > 65535) {
        error("Incorrect Port");
    }

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        error("Failed to create a socket channel");
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

    printf("server is running!\n");

    while (1){
        struct sockaddr_in client_addr = {0};
        socklen_t len = sizeof(client_addr);
        int new_sock_fd = accept(sock_fd, (struct sockaddr *) &client_addr, &len);
        if (new_sock_fd == -1) {
            printf("Failed to receive instructions from the client.");
            continue;
        } else {
            printf("IP:%s, PORT:%d [connected]\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        }
        pthread_t tid;
        struct t_info args;
        args.fd = new_sock_fd;
        args.addr = client_addr;
        pthread_create(&tid,NULL,handle_req,(void*)&args);
    }

    close(sock_fd);
}

#pragma clang diagnostic pop