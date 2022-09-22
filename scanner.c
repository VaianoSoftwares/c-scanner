#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <sys/wait.h>
#include <sys/mman.h>

#define DEFAULT_HOSTNAME "127.0.0.1"
#define DEFAULT_PORT 443
#define DEFAULT_CLIENTE "cliente1"
#define DEFAULT_POST "post1"
#define DEFAULT_TIPO "BARCODE"
#define MSG_LEN 4096

#define MSG_FORMAT  "POST /api/v1/badges/archivio HTTP/1.1\r\n"             \
                    "Host: %s\r\n"                                          \
                    "guest-token: %s\r\n"                                   \
                    "Content-Type: application/json; charset=utf-8\r\n"     \
                    "Content-Length: %zd\r\n\r\n"                           \
                    "%s"                                                

#define BODY_FORMAT "{\"barcode\":\"%s\","      \
                    "\"cliente\":\"%s\","       \
                    "\"postazione\":\"%s\","    \
                    "\"tipo\":\"%s\"}"

#define SERIAL_DIR "/dev/serial/by-id"
#define SCAN_BUF_SIZE 32
#define NDEVS 5
#define DEVNAME_LEN 128

#define SHM_NAME "open_devs"

typedef struct open_devs_t {
    char names[NDEVS][DEVNAME_LEN];
    uint8_t size;
} open_devs_t;

typedef struct body_args_t {
    char *cliente;
    char *postazione;
    char *tipo;
    char *barcode;
} body_args_t;

void throw_err(char *msg);
bool find_scanner(open_devs_t *od);
int connect_scanner(char *dev_name, struct termios *tio);
int conn_to_server(const char *hostname, int port);
SSL_CTX* init_CTX();
void show_certs(SSL *ssl);

int main(int argc, char *argv[]) {
    if(argc < 2) throw_err("main | invalid arguments: token is missing");

    // get cmd args
    char *token = argv[1];

    char *hostname = (argc >= 3 && strlen(argv[2]) > 0) ? argv[2] : DEFAULT_HOSTNAME;
    uint16_t port = (argc >= 7 && atoi(argv[6]) > 0) ? atoi(argv[6]) : DEFAULT_PORT;

    body_args_t ba;
    ba.cliente = (argc >= 4 && strlen(argv[3]) > 0) ? argv[3] : DEFAULT_CLIENTE;
    ba.postazione = (argc >= 4 && strlen(argv[3]) > 0) ? argv[3] : DEFAULT_CLIENTE;
    ba.tipo = (argc >= 6 && strlen(argv[5]) > 0) ? argv[5] : DEFAULT_TIPO;
    char scan_buf[SCAN_BUF_SIZE];
    ba.barcode = scan_buf;

    /*#################################################################################################################*/

    SSL_library_init();

    SSL_CTX *ctx = init_CTX();
    // connect to server
    int client_fd = conn_to_server(hostname, port);
    // make ssl connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);
    if(SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
        throw_err("main | SSL_connect");
    }

    printf("SSL connection enstablished.\n");

    show_certs(ssl);

    /*#################################################################################################################*/

    struct termios tio;
    int scan_fd;

    ssize_t read_scan;

    // open_devs shared memory
    size_t od_size = sizeof(open_devs_t);

    int shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if(shm_fd == -1) throw_err("main | shm_open");

    if(ftruncate(shm_fd, od_size) == -1) throw_err("main | ftruncate");

    open_devs_t *od =
        mmap(NULL, od_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if(od == MAP_FAILED) throw_err("main | mmap");

    /*#################################################################################################################*/

    int body_len = strlen(BODY_FORMAT) + strlen(ba.cliente) +
                   strlen(ba.postazione) + strlen(ba.tipo) + SCAN_BUF_SIZE;
    int req_len =
        strlen(MSG_FORMAT) + body_len + strlen(hostname) + strlen(argv[1]);

    char request[req_len], response[MSG_LEN], body_msg[body_len];
    
    int nbytes;

    /*#################################################################################################################*/

    pid_t pid;

    while(true) {
        // find available scanner device
        if(!find_scanner(od)) {
            waitpid(0, NULL, WNOHANG);
            sleep(5);
            continue;
        }

        printf("Scanner device found: %s.\n", od->names[od->size]);

        // create a subprocess for each device
        if((pid = fork()) == 0) {
            // connect device
            if((scan_fd = connect_scanner(od->names[od->size], &tio)) == -1) {
                od->size--;
                SSL_free(ssl);
                close(client_fd);
                SSL_CTX_free(ctx);
                throw_err("main | connect_scanner");
            }

            /*#################################################################################################################*/

            while(true) {
                // get barcode
                while((read_scan = read(scan_fd, scan_buf, sizeof(scan_buf))));
                if(!read_scan) {
                    fprintf(stderr, "Scanner has been unplugged.\n");
                    break;
                }

                // create msg request
                snprintf(body_msg, sizeof(body_msg), BODY_FORMAT, ba.barcode,
                    ba.cliente, ba.postazione, ba.tipo);
                snprintf(request, sizeof(request), MSG_FORMAT, hostname, token,
                    strlen(body_msg), body_msg);

                printf("-------------------------------------------------------------"
                    "--------------------------------------\n");
                printf("%s\n", request);
                printf("-------------------------------------------------------------"
                    "--------------------------------------\n");

                // send request
                if(SSL_write(ssl, request, strlen(request)) <= 0) {
                    ERR_print_errors_fp(stderr);
                    fprintf(stderr, "Unable to send request.\n");
                    break;
                }

                // recive response
                if((nbytes = SSL_read(ssl, response, sizeof(response))) <= 0) {
                    ERR_print_errors_fp(stderr);
                    fprintf(stderr, "No response.\n");
                    break;
                }
                response[nbytes] = 0;

                printf("%s\n", response);
            }

            od->size--;

            close(scan_fd);
            SSL_free(ssl);
            close(client_fd);
            SSL_CTX_free(ctx);

            /*#################################################################################################################*/

            exit(EXIT_SUCCESS);
        }
        else if (pid == -1) {
            od->size--;
            throw_err("main | fork"); 
        }

        waitpid(0, NULL, WNOHANG);
        sleep(5);
    }

    SSL_free(ssl);
    close(client_fd);
    SSL_CTX_free(ctx);

    return EXIT_SUCCESS;
}

void throw_err(char *msg) {
    perror(msg);
    if(!errno) exit(EXIT_FAILURE);
    exit(errno);
}

bool find_scanner(open_devs_t *od) {
    // max num of devices connected reached
    if(od->size >= NDEVS) return false;

    DIR *dp;
    struct dirent *dir;
    char dev_found[DEVNAME_LEN];

    // open serial devices directory
    if((dp = opendir(SERIAL_DIR)) == NULL) {
        fprintf(stderr,
              "Can't open serial devices directory: no device detected.\n");
        closedir(dp);
        return false;
    }

    // search for a serial device
    while((dir = readdir(dp)) != NULL) {
        // not a file: fail
        if(dir->d_type == DT_DIR) continue;

        for(int i=0; i<od->size; i++) {
            // get device full path
            sprintf(dev_found, "%s/%s", SERIAL_DIR, dir->d_name);

            // device not already opened
            if(strcmp(dir->d_name, od->names[i])) {
                strcpy(od->names[od->size++], dev_found);
                closedir(dp);
                return true;
            }
        }
    }

    closedir(dp);
    return false;
}

int connect_scanner(char *dev_name, struct termios *tio) {
    // open device on non-blocking read-only
    int fd;
    if((fd = open(dev_name, O_RDONLY | O_NONBLOCK)) == -1) {
        perror("connect_scanner | open");
        close(fd);
        return -1;
    }

    // device must be a tty
    if(!isatty(fd)) {
        fprintf(stderr, "connect_scanner | not a tty");
        close(fd);
        return -1;
    }

    // serial device setup
    bzero(tio, sizeof(*tio));

    tio->c_iflag= 0;
    tio->c_oflag= 0;
    tio->c_cflag= CS8 | CREAD | CLOCAL;           
    tio->c_lflag= 0;
    tio->c_cc[VMIN]= 1; 
    tio->c_cc[VTIME]= 5;

    cfsetospeed(tio,B9600);
    cfsetispeed(tio,B9600);      
 
    tcsetattr(fd,TCSANOW,tio);

    printf("Serial device %s connected.\n", dev_name);

    return fd;
}

int conn_to_server(const char *hostname, int port) {
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    // get hostname
    if((host = gethostbyname(hostname)) == NULL)
        throw_err("conn_to_server | gethostbyname");

    // create socket
    if((sd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
        throw_err("conn_to_server | socket");
    
    bzero(&addr, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    printf("Attempt to connect to %s:%d.\n", hostname, port);

    //attempt to connect
    while(connect(sd, (struct sockaddr*)&addr, sizeof(addr)))
        sleep(1);

    printf("Connection to %s:%d enstablished.\n", hostname, port);

    return sd;
}

SSL_CTX* init_CTX() {   
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */

    const SSL_METHOD *method = TLS_client_method();  /* Create new client-method instance */
    SSL_CTX *ctx = SSL_CTX_new(method);   /* Create new context */
    if(ctx == NULL) {
        ERR_print_errors_fp(stderr);
        throw_err("init_CTX | SSL_CTX_new");
    }

    return ctx;
}

void show_certs(SSL *ssl) {
    char *line;

    X509 *cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if(cert == NULL) {
        printf("Info: No client certificates configured.\n");
        return;
    } 

    printf("Server certificates:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Subject: %s\n", line);
    free(line); /* free the malloc'ed string */
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n", line);
    free(line);      /* free the malloc'ed string */
    X509_free(cert); /* free the malloc'ed certificate copy */
}