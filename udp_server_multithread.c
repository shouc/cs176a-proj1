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

// https://github.com/rxi/map/tree/master/src
// used it for mapping connections to its pipe

struct map_node_t;
typedef struct map_node_t map_node_t;

typedef struct {
    map_node_t **buckets;
    unsigned nbuckets, nnodes;
} map_base_t;

typedef struct {
    unsigned bucketidx;
    map_node_t *node;
} map_iter_t;


#define map_t(T)\
  struct { map_base_t base; T *ref; T tmp; }


#define map_init(m)\
  memset(m, 0, sizeof(*(m)))


#define map_deinit(m)\
  map_deinit_(&(m)->base)


#define map_get(m, key)\
  ( (m)->ref = map_get_(&(m)->base, key) )


#define map_set(m, key, value)\
  ( (m)->tmp = (value),\
    map_set_(&(m)->base, key, &(m)->tmp, sizeof((m)->tmp)) )


#define map_remove(m, key)\
  map_remove_(&(m)->base, key)


#define map_iter(m)\
  map_iter_()


#define map_next(m, iter)\
  map_next_(&(m)->base, iter)


void map_deinit_(map_base_t *m);
void *map_get_(map_base_t *m, const char *key);
int map_set_(map_base_t *m, const char *key, void *value, int vsize);
void map_remove_(map_base_t *m, const char *key);
map_iter_t map_iter_(void);
const char *map_next_(map_base_t *m, map_iter_t *iter);


typedef map_t(void*) map_void_t;
typedef map_t(char*) map_str_t;
typedef map_t(int) map_int_t;
typedef map_t(char) map_char_t;
typedef map_t(float) map_float_t;
typedef map_t(double) map_double_t;

struct map_node_t {
    unsigned hash;
    void *value;
    map_node_t *next;
    /* char key[]; */
    /* char value[]; */
};


static unsigned map_hash(const char *str) {
    unsigned hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) ^ *str++;
    }
    return hash;
}


static map_node_t *map_newnode(const char *key, void *value, int vsize) {
    map_node_t *node;
    int ksize = strlen(key) + 1;
    int voffset = ksize + ((sizeof(void*) - ksize) % sizeof(void*));
    node = malloc(sizeof(*node) + voffset + vsize);
    if (!node) return NULL;
    memcpy(node + 1, key, ksize);
    node->hash = map_hash(key);
    node->value = ((char*) (node + 1)) + voffset;
    memcpy(node->value, value, vsize);
    return node;
}


static int map_bucketidx(map_base_t *m, unsigned hash) {
    /* If the implementation is changed to allow a non-power-of-2 bucket count,
     * the line below should be changed to use mod instead of AND */
    return hash & (m->nbuckets - 1);
}


static void map_addnode(map_base_t *m, map_node_t *node) {
    int n = map_bucketidx(m, node->hash);
    node->next = m->buckets[n];
    m->buckets[n] = node;
}


static int map_resize(map_base_t *m, int nbuckets) {
    map_node_t *nodes, *node, *next;
    map_node_t **buckets;
    int i;
    /* Chain all nodes together */
    nodes = NULL;
    i = m->nbuckets;
    while (i--) {
        node = (m->buckets)[i];
        while (node) {
            next = node->next;
            node->next = nodes;
            nodes = node;
            node = next;
        }
    }
    /* Reset buckets */
    buckets = realloc(m->buckets, sizeof(*m->buckets) * nbuckets);
    if (buckets != NULL) {
        m->buckets = buckets;
        m->nbuckets = nbuckets;
    }
    if (m->buckets) {
        memset(m->buckets, 0, sizeof(*m->buckets) * m->nbuckets);
        /* Re-add nodes to buckets */
        node = nodes;
        while (node) {
            next = node->next;
            map_addnode(m, node);
            node = next;
        }
    }
    /* Return error code if realloc() failed */
    return (buckets == NULL) ? -1 : 0;
}


static map_node_t **map_getref(map_base_t *m, const char *key) {
    unsigned hash = map_hash(key);
    map_node_t **next;
    if (m->nbuckets > 0) {
        next = &m->buckets[map_bucketidx(m, hash)];
        while (*next) {
            if ((*next)->hash == hash && !strcmp((char*) (*next + 1), key)) {
                return next;
            }
            next = &(*next)->next;
        }
    }
    return NULL;
}


void map_deinit_(map_base_t *m) {
    map_node_t *next, *node;
    int i;
    i = m->nbuckets;
    while (i--) {
        node = m->buckets[i];
        while (node) {
            next = node->next;
            free(node);
            node = next;
        }
    }
    free(m->buckets);
}


void *map_get_(map_base_t *m, const char *key) {
    map_node_t **next = map_getref(m, key);
    return next ? (*next)->value : NULL;
}


int map_set_(map_base_t *m, const char *key, void *value, int vsize) {
    int n, err;
    map_node_t **next, *node;
    /* Find & replace existing node */
    next = map_getref(m, key);
    if (next) {
        memcpy((*next)->value, value, vsize);
        return 0;
    }
    /* Add new node */
    node = map_newnode(key, value, vsize);
    if (node == NULL) goto fail;
    if (m->nnodes >= m->nbuckets) {
        n = (m->nbuckets > 0) ? (m->nbuckets << 1) : 1;
        err = map_resize(m, n);
        if (err) goto fail;
    }
    map_addnode(m, node);
    m->nnodes++;
    return 0;
    fail:
    if (node) free(node);
    return -1;
}


void map_remove_(map_base_t *m, const char *key) {
    map_node_t *node;
    map_node_t **next = map_getref(m, key);
    if (next) {
        node = *next;
        *next = (*next)->next;
        free(node);
        m->nnodes--;
    }
}


map_iter_t map_iter_(void) {
    map_iter_t iter;
    iter.bucketidx = -1;
    iter.node = NULL;
    return iter;
}


const char *map_next_(map_base_t *m, map_iter_t *iter) {
    if (iter->node) {
        iter->node = iter->node->next;
        if (iter->node == NULL) goto nextBucket;
    } else {
        nextBucket:
        do {
            if (++iter->bucketidx >= m->nbuckets) {
                return NULL;
            }
            iter->node = m->buckets[iter->bucketidx];
        } while (iter->node == NULL);
    }
    return (char*) (iter->node + 1);
}

// end map definition

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
    int read_fd;
    char* key;
};

map_str_t conn_to_fd;

//#define DEBUG


#define update_timeout(sec, usec) \
    timeout.tv_sec = sec;\
    timeout.tv_usec = usec;\
    FD_ZERO(&set);\
    FD_SET(info->read_fd, &set);\
    rv = select(info->read_fd + 1, &set, NULL, NULL, &timeout);


void* handle_req(void*  arg){
    struct t_info* info=(struct s_info*)arg;
    char _msg_len[MAX_LEN_PACKET];
    struct timeval timeout;
    fd_set set;
    int rv;
    char __internal_msg_len[10];
    int __internal_msg_len_i;

#ifdef DEBUG
    time_t t;
    srand((unsigned) time(&t));
#endif

    start_handle:
    // remove timeout

    // get len
#define get_internal_msg_len \
    if (read(info->read_fd, __internal_msg_len, 9) == -1){\
        printf("Failed to receive instructions from the client1.");\
        goto start_handle;\
    }\
    __internal_msg_len_i = atoi(__internal_msg_len);

update_timeout(1e8, 0)
    get_internal_msg_len
    __internal_msg_len_i = atoi(__internal_msg_len);
    if (read(info->read_fd, _msg_len, __internal_msg_len_i) == -1){
        FAILED_TO_RECV
    }


    int msg_len = atoi(_msg_len);
    printf("%d", msg_len);


    char command[MAX_LEN_PACKET] = {0};
    update_timeout(0, 50000)
    if (rv < 1) {
        printf("timeout");
        // timeout
        goto start_handle;
    }

    get_internal_msg_len

    if (read(info->read_fd, command, __internal_msg_len_i) == -1){
        printf("Failed to receive instructions from the client1.");
        goto start_handle;
    }

    if (strlen(command) != msg_len){
        printf("Failed to receive instructions from the client2.");
        goto start_handle;
    }
    printf("%s writes %s\n", info->key, "ack");
    if (sendto(info->fd, (const char *) "ACK", sizeof("ACK"), 0, &info->addr,
               sizeof(info->addr)) == -1) {
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
//    printf("1");
    char c_msg_len[100];
    sprintf(c_msg_len, "%d", send_size);
#ifdef DEBUG
    if (rand() % 10 != 1) {
#endif
    printf("%s writes %s\n", info->key, c_msg_len);

    if (sendto(info->fd, c_msg_len, strlen(c_msg_len), 0, &info->addr,
               sizeof(info->addr)) == -1) {
        printf("Failed write size.\n");
        goto send_len;
    }
    printf("size: %d\n", send_size);
#ifdef DEBUG
    } else {
        printf("Didn't send size packet");
    }
#endif
    // ACK\0
    char ack_msg[4] = {0};
//    printf("-1\n");

    update_timeout(0, 500)
    if (rv < 1) {
        // timeout
        printf("timeout3\n");
        goto send_len;
    }
    get_internal_msg_len
//    printf("0");

    if (read(info->read_fd, ack_msg, __internal_msg_len_i) == -1){
        printf("Failed to recv ack.\n");
        goto send_len;
    }
//    printf("1\n");

    if (!(ack_msg[0] == 'A' && ack_msg[1] == 'C' && ack_msg[2] == 'K')){
        printf("Failed to recv ack.\n");
        goto send_len;
    }
//    printf("2\n");

    while (counter != -1){
        unsigned int current_data_start_pos = index * chunk_size;
        unsigned int current_data_len = counter == 0 ? send_size % chunk_size : chunk_size;
        failed_count = 0;
        printf("sending %d+%d\n", current_data_start_pos, current_data_len);

send_data:
        failed_count++;
//        printf("-i7\n");

        if (failed_count == 4){
            printf("File transmission failed\n");
            return NULL;
        }
//        printf("-i8\n");



#ifdef DEBUG
        if (rand() % 10 != 1) {
#endif
//        printf("3");/**/

        printf("%s writes data\n", info->key);

        if (sendto(info->fd, send_buff + current_data_start_pos, current_data_len, 0, &info->addr,
                   sizeof(info->addr)) ==
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
//        printf("4");

        update_timeout(0, 1500)

        if (rv < 1) {
            // timeout
            printf("timeout2");
            goto send_data;
        }
        get_internal_msg_len
//        printf("5");

        if (read(info->read_fd, ack_msg, __internal_msg_len_i) == -1){
            printf("Failed to recv ack.\n");
            printf("6\n");
            goto send_data;
        }
//        printf("6");

        if (!(ack_msg[0] == 'A' && ack_msg[1] == 'C' && ack_msg[2] == 'K')){
            printf("Failed to recv ack.\n");
            printf("7\n");
            goto send_data;
        }
        index++;
        counter--;
    }
//    close(info->read_fd);
//    map_remove(&conn_to_fd, info->key);
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

    int one = 5;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));


    printf("server is runningz!\n");

    map_init(&conn_to_fd);

    struct sockaddr_in client_addr = {0};
    socklen_t len = sizeof(client_addr);


    while (1) {

        char data[MAX_LEN_PACKET];
        struct sockaddr_in inc_client_addr;

        socklen_t inc_client_size = sizeof(inc_client_addr);
        int bytes_read = recvfrom(sock_fd, data, sizeof(data), 0,
                                  &inc_client_addr, &inc_client_size);

        if (bytes_read == -1) {
            close(sock_fd);
            printf("failed to receive");
//            return 0;
        }
        char key[100];
        sprintf(key, "%s:%d", inet_ntoa(inc_client_addr.sin_addr), inc_client_addr.sin_port);

        int* fd = map_get(&conn_to_fd, key);
        if (fd) {
            // len(MAX_LEN_PACKET) = 9
#define make_content \
    char new_data[MAX_LEN_PACKET + 9];\
    sprintf(new_data, "%09d%s", bytes_read, data);
            make_content
            printf("write to pipe %s: %s\n", key, new_data);
            int k = write(*fd, new_data, bytes_read + 9);
        } else {
            int new_fd[2];
            if (pipe(new_fd) < 0)
                printf("failed to create pipe");
            map_set(&conn_to_fd, key, new_fd[1]);
            make_content
            printf("new conn: %s\n", key);
            pthread_t tid;
            struct t_info args;
            args.fd = sock_fd;
            args.read_fd = new_fd[0];
            args.addr = inc_client_addr;
            args.key = key;
            printf("write to pipe %s: %s\n", key, new_data);
            pthread_create(&tid, NULL, handle_req, (void*)&args);
            int k = write(new_fd[1], new_data, bytes_read + 9);
        }
    }
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
