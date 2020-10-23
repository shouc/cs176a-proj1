//
// Created by Shou C on 10/8/20.
//
// Citations:
// Converting hostname to IP from
// https://stackoverflow.com/questions/3060950/how-to-get-ip-address-from-sock-structure-in-c
// UDP timeout implementation from
// https://stackoverflow.com/questions/13547721/udp-socket-set-timeout
// Concept for UDP receiving infinite len message (same as TCP)
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
#include <time.h>
#define RECV_SIZE 1024
#define error(msg) \
    printf(msg);\
    exit(0);
#define MAX_LEN_PACKET 1500
#define update_timeout(sec, usec) \
    timeout.tv_sec = sec;\
    timeout.tv_usec = usec;\
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,\
    sizeof(timeout));
//#define DEBUG


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

int main(int argc, char *argv[])
{
    // check
    char hostname[100]; // = "127.0.0.1";

#ifdef DEBUG
    time_t t;
    srand((unsigned) time(&t));
#endif

//    char command[1024] = "lsof > p.txt";
//    int port = 9998;
    printf("Enter server name or IP address: ");
    scanf("%s", hostname);
    struct hostent* server_info = gethostbyname(hostname);
    if (server_info == NULL) {
        error("Could not connect to server.\n");
    }
    int port;
    printf("Enter port: ");
    scanf("%d", &port);
    if (port >= 65535 || port <= 0) {
        error("Invalid port number.");
    }

    char command[MAX_LEN_PACKET] = {0};
    printf("Enter command: ");
//    scanf("%s", command);
    fgets(command, 2, stdin);
    fgets(command, MAX_LEN_PACKET, stdin);
    strtok(command, "\n");


    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock_fd == -1) {
        error("Could not connect to server.\n");
    }


    char file_name[MAX_LEN_PACKET] = {0};
    unsigned char has_specified_file = parse_command(command, file_name);

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
send_data: // start to send command
    failed_count++;
    if (failed_count == 5){
        // all three attempts are used
        printf("Failed to send command. Terminating.\n");
        close(sock_fd);
        return 0;
    }

    char c_msg_len[100]={0};
    // format int size to string
    sprintf(c_msg_len, "%lu", strlen(command));
#ifdef DEBUG
    if (rand() % 3 != 1) {
#endif
        // write the command size
        if (write(sock_fd, c_msg_len, strlen(c_msg_len)) == -1) {
            goto send_data;
        }
#ifdef DEBUG
    } else {
        printf("Didn't send size packet\n");
    }
    if (rand() % 3 != 1){
#endif
        // write the command
        if (write(sock_fd, command, strlen(command)) == -1){
            goto send_data;
        }
#ifdef DEBUG
    } else {
        printf("Didn't send data packet");
    }
#endif

    struct timeval timeout;
    update_timeout(1, 0)
    // receive ACK\0
    char ack_msg[4] = {0};
    if (recv(sock_fd, ack_msg, 4, 0) == -1){
#ifdef DEBUG_PRINT
        printf("Failed to recv ack.\n");
#endif
        goto send_data;
    }
    // compare chars received with chars A C K
    if (!(ack_msg[0] == 'A' && ack_msg[1] == 'C' && ack_msg[2] == 'K')){
#ifdef DEBUG_PRINT
        printf("Failed to recv ack.\n");
#endif
        goto send_data;
    }
    // send command successfully after here

    // get size
    update_timeout(0, 0) // reset timeout
    char _msg_len[MAX_LEN_PACKET];
    // receive the length of message
    if (recv(sock_fd, _msg_len, sizeof(_msg_len), 0) == -1){
        error("Failed to receive size.");
    }
    int msg_len = atoi(_msg_len);

    // acknowledge size is received
    if (write(sock_fd, "ACK", sizeof("ACK")) == -1){
        error("Failed to send ack. Terminating.\n");
    }

    // initialize buffer
    int init_size = RECV_SIZE;
    int cter = 0;
    char resp_buff[MAX_LEN_PACKET];
    char* filename = has_specified_file ? file_name : "output.txt";
    FILE *fp;
    fp = fopen(filename, "w+");
    while (1){
        int _failed_count = 0;
start_handle: // receive output
        _failed_count++;
        if (_failed_count == 5){
            // three attempts used
            printf("File transmission failed");
            close(sock_fd);
            return 0;
        }
        // set timeout to 500ms
        update_timeout(0, 500000)
        // receive RECV_SIZE bytes of data
        int bytes_read = recv(sock_fd, resp_buff, RECV_SIZE, 0);
        if (bytes_read == -1){
#ifdef DEBUG_PRINT
            time_t ltime; /* calendar time */
            ltime=time(NULL); /* get current cal time */
            printf("%s\n",asctime( localtime(&ltime) ) );
            printf("Failed to receive instructions from the client.\n");
#endif
            goto start_handle;
        }
#ifdef DEBUG_PRINT
        printf("got %d + RECV_SIZE\n", cter);
#endif
        // acknowledge data
        if (write(sock_fd, "ACK", sizeof("ACK")) == -1){
            error("Failed to send ack. Terminating.\n");
        }
        resp_buff[bytes_read] = '\0';
        fprintf(fp, "%s", resp_buff);
#ifdef DEBUG_PRINT
        printf("acked %d + RECV_SIZE\n", cter);
#endif
        cter += bytes_read;
        if (cter >= msg_len){
            // read enough data
            break;
        }
//        if (cter == sizeof(resp_buff) - 1){
//            // buffer is not enough
//            resp_buff = realloc(resp_buff, sizeof(char)*(init_size += RECV_SIZE));
//        }
    }

    if (strlen(resp_buff) < 1){
        close(sock_fd);
        error("File transmission failed.\n");
    }


    // save the file
    printf("\nFile %s saved.\n", filename);
    fclose(fp);

    // close the socket
    close(sock_fd);
    return 0;
}
