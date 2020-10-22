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
#define FAILED_TO_RECV\
    printf("Failed to receive instructions from the client3.");\
    return NULL;
unsigned char parse_command(char* cmd, char* file_name) {
    unsigned char last_stmt_flag = 0;
    unsigned char file_flag = 0;
    int fi = 0;
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
    int fd;
};
//#define DEBUG


#define update_timeout(sec, usec) \
    timeout.tv_sec = sec;\
    timeout.tv_usec = usec;\
    setsockopt(info->fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,\
    sizeof(timeout));

void* handle_req(struct t_info* arg){
    struct t_info* info=(struct t_info*)arg;
    char _msg_len[MAX_LEN_PACKET];
    struct timeval timeout;
    struct sockaddr cliaddr;
    int clisize = sizeof(cliaddr);
#ifdef DEBUG
    time_t t;
    srand((unsigned) time(&t));
#endif
start_handle:
    // remove timeout
    update_timeout(0, 0)
    if (recvfrom(info->fd, _msg_len, sizeof(_msg_len), 0, &cliaddr, &clisize) == -1){
        FAILED_TO_RECV
    }

    int msg_len = atoi(_msg_len);

    // set timeout
    update_timeout(0, 500)

    char command[MAX_LEN_PACKET] = {0};
    if (recvfrom(info->fd, command, sizeof(command), 0, &cliaddr, &clisize) == -1){
        printf("Failed to receive instructions from the client1.");
        goto start_handle;
    }

    if (strlen(command) != msg_len){
        printf("Failed to receive instructions from the client2.");
        goto start_handle;
    }
    if (sendto(info->fd, (const char *) "ACK", sizeof("ACK"), 0, &cliaddr, clisize) == -1) {
        error("Failed to send ack. Terminating.\n");
    }
    char file_name[MAX_LEN_PACKET] = {0};

    parse_command(command, file_name);

    int init_size = 16;
    char *send_buff = realloc(NULL, sizeof(char) * init_size);
    int cter;
    system(command);

    int c;
    cter = 0;
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
    // chunk
    unsigned int send_size = strlen(send_buff);
    unsigned int chunk_size = 16;
    unsigned int counter = send_size / chunk_size;
    unsigned int index = 0;

    update_timeout(1, 0)
    int failed_count = 0;
send_len:
    failed_count++;
    if (failed_count == 4){
        printf("File transmission failed");
        return NULL;
    }
    char c_msg_len[100];
    sprintf(c_msg_len, "%d", send_size);
#ifdef DEBUG
    if (rand() % 10 != 1) {
#endif
        if (sendto(info->fd, c_msg_len, strlen(c_msg_len), 0, &cliaddr, clisize) == -1) {
            printf("Failed write size.\n");
            goto send_len;
        }
#ifdef DEBUG
    } else {
        printf("Didn't send size packet");
    }
#endif
    // ACK\0
    char ack_msg[4] = {0};
    if (recvfrom(info->fd, ack_msg, 4, 0, &cliaddr, &clisize) == -1){
        printf("Failed to recv ack.\n");
        goto send_len;
    }
    if (!(ack_msg[0] == 'A' && ack_msg[1] == 'C' && ack_msg[2] == 'K')){
        printf("Failed to recv ack.\n");
        goto send_len;
    }

    while (counter != -1){
        unsigned int current_data_start_pos = index * chunk_size;
        unsigned int current_data_len = counter == 0 ? send_size % chunk_size : chunk_size;
        failed_count = 0;

send_data:
        failed_count++;
        if (failed_count == 4){
            printf("File transmission failed");
            return NULL;
        }


#ifdef DEBUG
        if (rand() % 10 != 1) {
#endif
        if (sendto(info->fd, send_buff + current_data_start_pos, current_data_len, 0, &cliaddr, clisize) ==
                -1) {
                printf("Failed write x.\n");
                goto send_data;
            }
#ifdef DEBUG
        } else {
                printf("Didn't send data packet %d - %d",
                        current_data_start_pos,
                        current_data_len);
        }
#endif
        // ACK\0
        char ack_msg[4] = {0};
        if (recvfrom(info->fd, ack_msg, 4, 0, &cliaddr, &clisize) == -1){
            printf("Failed to recv ack.\n");
            goto send_data;
        }
        if (!(ack_msg[0] == 'A' && ack_msg[1] == 'C' && ack_msg[2] == 'K')){
            printf("Failed to recv ack.\n");
            goto send_data;
        }
        index++;
        counter--;
    }
    free(send_buff);
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        error("Please specify a port number");
    }

    int port = atoi(argv[1]);
    if (port < 0 || port > 65535) {
        error("Incorrect Port");
    }
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
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

    printf("server is running!\n");

    struct sockaddr_in client_addr = {0};
    socklen_t len = sizeof(client_addr);
    pthread_t tid;
    struct t_info args;
    args.fd = sock_fd;
    args.addr = client_addr;
    while (1)
        handle_req(&args);
//    char buffer[1000];
//    struct sockaddr_in servaddr, cliaddr;
//    int k = sizeof(cliaddr);
//    int n = recvfrom(sock_fd, (char *)buffer, 1000,
//                 MSG_WAITALL, ( struct sockaddr *) &cliaddr,
//                 &k);
//    printf("%d", n);
//    close(sock_fd);
}

#pragma clang diagnostic pop
