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
#include <time.h>

#define error(msg) \
    printf(msg);\
    exit(0);
const unsigned int MAX_LEN_PACKET = 1500;
#define update_timeout(sec, usec) \
    timeout.tv_sec = sec;\
    timeout.tv_usec = usec;\
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,\
    sizeof(timeout));
#define DEBUG
int main(int argc, char *argv[])
{
    // check
//    char server_addr_c[100] = "127.0.0.1";

#ifdef DEBUG
    time_t t;
    srand((unsigned) time(&t));
#endif

    char command[1024];
    printf("Enter command: ");
    scanf ("%[^\n]s", command);
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

    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
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

    unsigned int failed_count = 0;
send_data:
    if (failed_count == 3){
        printf("Failed to send command. Terminating.");
        close(sock_fd);
        return NULL;
    }
    failed_count++;

    char c_msg_len[100]={0};
    // size packet
    sprintf(c_msg_len, "\5%d", strlen(command));
    printf("%s %s", c_msg_len, command);
#ifdef DEBUG
    if (rand() % 3 != 1) {
#endif
        if (write(sock_fd, c_msg_len, strlen(c_msg_len)) == -1) {
            printf("Failed write size.\n");
            goto send_data;
        }
#ifdef DEBUG
    } else {
        printf("Didn't send size packet");
    }
    if (rand() % 3 != 1){
#endif
        if (write(sock_fd, command, strlen(command)) == -1){
            printf("Failed write x.\n");
            goto send_data;
        }
#ifdef DEBUG
    } else {
        printf("Didn't send data packet");
    }
#endif

    struct timeval timeout;
    update_timeout(1, 0)
    // ACK\0
    char ack_msg[4] = {0};
    if (recv(sock_fd, ack_msg, 4, 0) == -1){
        printf("Failed to recv ack.\n");
        goto send_data;
    }
    if (!(ack_msg[0] == 'A' && ack_msg[1] == 'C' && ack_msg[2] == 'K')){
        printf("Failed to recv ack.\n");
        goto send_data;
    }

    // send msg successfully
    int init_size = 32;
    int cter = 0;
    char* resp_buff = realloc(NULL, sizeof(char) * init_size);
    while (1){
start_handle:
        update_timeout(0, 0)
        char _msg_len[MAX_LEN_PACKET];
        if (recv(sock_fd, _msg_len, sizeof(_msg_len), 0) == -1){
            printf("Failed to receive size.");
            goto start_handle;
        }

        if (_msg_len[0] != '\5'){
            printf("expecting msg len packet\n");
            goto start_handle;
        }

        int msg_len = atoi(_msg_len + 1);


        // set timeout
        update_timeout(0, 500)

        if (recv(sock_fd, resp_buff + cter, msg_len, 0) == -1){
            printf("Failed to receive instructions from the client.");
            goto start_handle;
        }
        if (write(sock_fd, "ACK", sizeof("ACK")) == -1){
            error("Failed to send ack. Terminating.\n");
        }
        if ((resp_buff + cter)[0] == '\4'){
            break;
        }
        cter += msg_len;
        if (cter == sizeof(resp_buff) - 1){
            resp_buff = realloc(resp_buff, sizeof(char)*(init_size += 32));
        }
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
