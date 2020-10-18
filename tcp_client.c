//
// Created by Shou C on 10/8/20.
//

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
const unsigned int MAX_LEN_PACKET = 1500;

int main(int argc, char *argv[])
{
    // check
//    char server_addr_c[100] = "127.0.0.1";
    char hostname[1500];
    printf("Enter server name or IP address: ");
    scanf("%s", hostname);
    struct hostent* server_info = gethostbyname(hostname);
    if (server_info == NULL) {
        error("Could not connect to server.\n");
    }

//
//    int port = 9989;
    int port;
    printf("Enter port: ");
    scanf("%d", &port);
    if (port >= 65535 || port <= 0) {
        error("Invalid port number.");
    }

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
    if (connect(sock_fd, (const struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
        error("Could not connect to server.\n");
    }

    //    char command[1024] = "cat /etc/apache2/httpd.conf > httpd.txt";
    char command[1024];
    printf("Enter command: ");
    scanf("%s", command);

    if (write(sock_fd, command, sizeof(command)) == -1){
        error("Failed to send command. Terminating.\n");
    }

    int init_size = 32;
    int cter = 0;
    char* resp_buff = realloc(NULL, sizeof(char) * init_size);
    ssize_t bytes_read = 1;
    unsigned char recv_start = 0;
    while (bytes_read > 0) {
        if (recv_start == 1){
            bytes_read = recv(sock_fd, resp_buff + cter, 32, MSG_DONTWAIT);
        } else {
            recv_start++;
            bytes_read = recv(sock_fd, resp_buff + cter, 32, 0);
        }
        cter += bytes_read;
        if (cter == sizeof(resp_buff) - 1){
            resp_buff = realloc(resp_buff, sizeof(char)*(init_size += 32));
        }
        if (bytes_read < 32) break;
    }

    if (strlen(resp_buff) < 1){
        error("Did not receive response.\n");
    }
    if (resp_buff[0] == '\3')
        printf("Response received: %s\n", ++resp_buff);
    else if (resp_buff[0] == '\2') {
        unsigned int start_pos = 0;
        char file_name[MAX_LEN_PACKET];
        for (int i = 0; i < strlen(resp_buff); ++i) {
            file_name[i] = resp_buff[i+1];
            if (resp_buff[i+2] == '\2'){
                file_name[i+1] = '\0';
                start_pos = i+3;
                break;
            }
        }
        resp_buff += start_pos;
        printf("File %s saved.\n", file_name);
        FILE *fp;
        fp = fopen(file_name, "w+");
        fprintf(fp, "%s", resp_buff);
        fclose(fp);
    }


    close(sock_fd);
    return 0;

}
