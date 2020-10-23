//
// Created by Shou C on 10/8/20.
//
//
// Citations:
// The map implementation for mapping connections to its pipe is copied from
// https://github.com/rxi/map/
// Concepts of event-based system borrowed partly from
// https://linuxprograms.wordpress.com/2008/01/23/piping-in-threads/
//
// References:
// Timeout: https://linux.die.net/man/3/fd_set
// Read: https://linux.die.net/man/3/read



#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>
#define RECV_SIZE 1024

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

#define MAX_LEN_PACKET 1500


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

#define get_internal_msg_len \
    if (read(info->read_fd, __internal_msg_len, 9) == -1){\
        printf("Unexpected: failed to read.\n");\
        goto start_handle;\
    }\
    __internal_msg_len_i = atoi(__internal_msg_len);
void* handle_req(void*  arg){
    struct t_info* info=(struct t_info*)arg;
    struct timeval timeout;
    fd_set set;
    int rv;
    char __internal_msg_len[10];
    int __internal_msg_len_i;

#ifdef DEBUG
    time_t t;
    srand((unsigned) time(&t));
#endif
    int failed_count = 0;
start_handle:
    failed_count++;
    if (failed_count == 5){
        // all three attempts are used
        printf("Failed to receive instructions from the client.");
        goto cleanup;
    }
    // reset timeout
    update_timeout(0, 0)
    get_internal_msg_len
    // read command size
    char _msg_len[MAX_LEN_PACKET];
    if (read(info->read_fd, _msg_len, __internal_msg_len_i) == -1){
#ifdef DEBUG_PRINT
        printf("Failed to receive instructions from the client.");
#endif
        goto cleanup;
    }

    // convert command size to int
    int msg_len = atoi(_msg_len);

    char command[MAX_LEN_PACKET] = {0};

    // timeout 500ms for fd
    update_timeout(0, 500000)
    if (rv < 1) {
#ifdef DEBUG_PRINT
        printf("timeout");
#endif
        // timeout
        goto start_handle;
    }
    get_internal_msg_len
    // read the command
    if (read(info->read_fd, command, __internal_msg_len_i) == -1){
#ifdef DEBUG_PRINT
        printf("Failed to receive instructions from the client.");
#endif
        goto start_handle;
    }

    // check command size against strlen(command)
    if (strlen(command) != msg_len){
#ifdef DEBUG_PRINT
        printf("Failed to receive instructions from the client.");
#endif
        goto start_handle;
    }


    // ack the command
    if (sendto(info->fd, (const char *) "ACK", sizeof("ACK"), 0, &info->addr,
               sizeof(info->addr)) == -1) {
#ifdef DEBUG_PRINT
        printf("Failed to send ack. Terminating.\n");
#endif
        goto cleanup;
    }

    // same as tcp...
    char file_name[MAX_LEN_PACKET] = {0};
    parse_command(command, file_name);

    int init_size = 1024;
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
                send_buff = realloc(send_buff, sizeof(char)*(init_size += 1024));
        }
        fclose(file);
    }

    send_buff[cter++]='\0';

    // chunk parameters
    unsigned int send_size = strlen(send_buff);
    unsigned int chunk_size = RECV_SIZE;
    unsigned int counter = send_size / chunk_size;
    unsigned int index = 0;

    update_timeout(1, 0)

    failed_count = 0;
send_len: // send data length
    failed_count++;
    if (failed_count == 5){
        // used up all attempts
        printf("File transmission failed");
        goto cleanup_with_buff;
    }

    // make data length to a string
    char c_msg_len[100];
    sprintf(c_msg_len, "%d", send_size);
#ifdef DEBUG
    if (rand() % 10 != 1) {
#endif
#ifdef DEBUG_PRINT
    printf("%s writes %s\n", info->key, c_msg_len);
#endif
    // send the data len

    if (sendto(info->fd, c_msg_len, strlen(c_msg_len), 0, &info->addr,
               sizeof(info->addr)) == -1) {
#ifdef DEBUG_PRINT
        printf("Failed write size.\n");
#endif
        goto send_len;
    }
#ifdef DEBUG_PRINT
    printf("size: %d\n", send_size);
#endif
#ifdef DEBUG
    } else {
        printf("Didn't send size packet");
    }
#endif
    // ACK\0
    char ack_msg[4] = {0};


    // wait 1s for the ack
    update_timeout(1, 0)
    if (rv < 1) {
        // timeout
#ifdef DEBUG_PRINT
        printf("timeout3\n");
#endif
        goto send_len;
    }
    get_internal_msg_len
    // receive ack
    if (read(info->read_fd, ack_msg, __internal_msg_len_i) == -1){
#ifdef DEBUG_PRINT
        printf("Failed to recv ack.\n");
#endif
        goto send_len;
    }
    // compare to str 'ACK'
    if (!(ack_msg[0] == 'A' && ack_msg[1] == 'C' && ack_msg[2] == 'K')){
#ifdef DEBUG_PRINT
        printf("Failed to recv ack.\n");
#endif
        goto send_len;
    }

    while (counter != -1){
        unsigned int current_data_start_pos = index * chunk_size;
        unsigned int current_data_len = counter == 0 ? send_size % chunk_size : chunk_size;
        failed_count = 0;

send_data:
        failed_count++;
        if (failed_count == 5){
            // all attempts used
#ifdef DEBUG_PRINT
            time_t ltime; /* calendar time */
            ltime=time(NULL); /* get current cal time */
            printf("%s",asctime( localtime(&ltime) ) );
#endif
            printf("File transmission failed.\n");
            goto cleanup_with_buff;
        }

#ifdef DEBUG
        if (rand() % 10 != 1) {
#endif
#ifdef DEBUG_PRINT
        printf("%s writes data\n", info->key);
        // start to write data
        time_t ltime; /* calendar time */
        ltime=time(NULL); /* get current cal time */
        printf("send at %d-%d at %s",current_data_start_pos, current_data_len,
                asctime( localtime(&ltime) ) );
#endif
        if (sendto(info->fd, send_buff + current_data_start_pos, current_data_len, 0, &info->addr,
                   sizeof(info->addr)) ==
            -1) {
#ifdef DEBUG_PRINT
            printf("Failed write data.\n");
#endif
            goto send_data;
        }
#ifdef DEBUG
        } else {
                printf("Didn't send data packet %d - %d",
                        current_data_start_pos,
                        current_data_len);
        }
#endif
        // get ack
        char _ack_msg[4] = {0};
        // wait 1s for ACK
        update_timeout(1, 0)
        if (rv < 1) {
            // timeout
            printf("timeout2");
            goto send_data;
        }
        get_internal_msg_len
        // recv ack
        if (read(info->read_fd, _ack_msg, __internal_msg_len_i) == -1){
            printf("Failed to recv ack.\n");
            goto send_data;
        }
#ifdef DEBUG_PRINT
        printf("got ack at %d-%d at %s",current_data_start_pos, current_data_len,
               asctime( localtime(&ltime) ) );
#endif
        // compare to str 'ACK'
        if (!(ack_msg[0] == 'A' && ack_msg[1] == 'C' && ack_msg[2] == 'K')){
#ifdef DEBUG_PRINT
            printf("Failed to recv ack.\n");
#endif
            goto send_data;
        }
        index++;
        counter--;
    }
cleanup_with_buff:
    free(send_buff);
cleanup:
    close(info->read_fd);
    map_remove(&conn_to_fd, info->key);
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        error("Please specify a port number.\n");
    }
    int port = atoi(argv[1]);
    if (port < 0 || port > 65535) {
        error("Invalid port number.\n");
    }
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd == -1) {
        assert(0);
        error("Failed to create a socket channel\n");
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1){
        assert(0);
        error("Failed to bind.\n");
    }

    int one = 5;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

#ifdef DEBUG_PRINT
    printf("server is runningz!\n");
#endif

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
            assert(0);
            printf("Socket has been closed\n");
            return 0;
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
#ifdef DEBUG_PRINT
            printf("write to pipe %s: %s\n", key, new_data);
#endif
            int k = write(*fd, new_data, bytes_read + 9);
        } else {
            int new_fd[2];
            if (pipe(new_fd) < 0){
                assert(0);
                printf("Failed to create pipe\n");
            }
            map_set(&conn_to_fd, key, new_fd[1]);
            make_content
#ifdef DEBUG_PRINT
            printf("new conn: %s\n", key);
#endif
            pthread_t tid;
            struct t_info* args = malloc(sizeof(struct t_info));
            args->fd = sock_fd;
            args->read_fd = new_fd[0];
            args->addr = inc_client_addr;
            args->key = key;
#ifdef DEBUG_PRINT
            printf("write to pipe %s: %s\n", key, new_data);
#endif
            pthread_create(&tid, NULL, handle_req, (void*)args);
            int k = write(new_fd[1], new_data, bytes_read + 9);
        }
    }
}

#pragma clang diagnostic pop
