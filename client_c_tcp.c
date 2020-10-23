//
// Created by Shou C on 10/8/20.
//
// Citations:
// Converting hostname to IP from
// https://stackoverflow.com/questions/3060950/how-to-get-ip-address-from-sock-structure-in-c
// TCP receiving infinite len message
// https://stackoverflow.com/questions/2333827/c-c-tcp-socket-class-receive-problem
//
// References:
// Recv: https://man7.org/linux/man-pages/man2/recv.2.html


#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>

#define error(msg) \
    printf(msg);\
    exit(0);
#define MAX_LEN_PACKET 1500
unsigned char parse_command(char* cmd, char* file_name) {
    unsigned char last_stmt_flag = 0;
    unsigned char file_flag = 0;
    int fi = 0;
    char* tmp_dir = "> /tmp/output";
    for (int i = 0; i < strlen(cmd); ++i) {
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
#define update_timeout(sec, usec) \
    timeout.tv_sec = sec;\
    timeout.tv_usec = usec;\
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,\
    sizeof(timeout));
int main(int argc, char *argv[]){
    // check
    struct timeval timeout;

//    char hostname[100] = "127.0.0.1";
    char hostname[1500];
    printf("Enter server name or IP address: ");
    scanf("%s", hostname);
    struct hostent* server_info = gethostbyname(hostname);
    if (server_info == NULL) {
        error("Could not connect to server.\n");
    }

//
//    int port = 9982;
    int port;
    printf("Enter port: ");
    scanf("%d", &port);
    if (port >= 65535 || port <= 0) {
        error("Invalid port number.\n");
    }

    // make file descriptor
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(sock_fd == -1) {
        error("Could not connect to server.\n");
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    bcopy((char *)server_info->h_addr,
          (char *)&server_addr.sin_addr.s_addr,
          server_info->h_length);
    // connect to server
    if (connect(sock_fd, (const struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
        error("Could not connect to server.\n");
    }

    char command[MAX_LEN_PACKET];
    printf("Enter command: ");
    fgets(command, 2, stdin);
    fgets(command, MAX_LEN_PACKET, stdin);
    strtok(command, "\n");


    // get the file name from command (e.g. ps -ax > a.txt => a.txt)
    char file_name[MAX_LEN_PACKET] = {0};
    unsigned char has_specified_file = parse_command(command, file_name);

    // write the command
    if (write(sock_fd, command, sizeof(command)) == -1){
        error("Failed to send command. Terminating.\n");
    }

    // initialize buffer
    char* filename = has_specified_file ? file_name : "output.txt";

    FILE *fp;
    fp = fopen(filename, "w+");
    char resp_buff[MAX_LEN_PACKET];
    ssize_t bytes_read = 1;
    int cter = 0;
    while (bytes_read > 0) {
        // receive 32 bytes each time
        bytes_read = recv(sock_fd, resp_buff, 32, 0);
        resp_buff[bytes_read] = '\0';
        fprintf(fp, "%s", resp_buff);
        cter += bytes_read;
    }
    // buffer is empty
    if (cter < 1){
        printf("Did not receive response.\n");
        return 0;
    }

    // if no file name specified, use output.txt
    printf("\nFile %s saved.\n", filename);

    // cleanup
    fclose(fp);
    close(sock_fd);
    return 0;
}
