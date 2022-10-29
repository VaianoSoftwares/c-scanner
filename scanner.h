#define DEFAULT_HOSTNAME    "127.0.0.1"
#define DEFAULT_PORT        443
#define DEFAULT_CLIENTE     "cliente1"
#define DEFAULT_POST        "post1"
#define DEFAULT_TIPO        "BARCODE"
#define MSG_LEN             4096

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


#define SCAN_BUF_SIZE   32
#define NDEVS           5

typedef struct body_args_t {
    const char *cliente;
    const char *postazione;
    const char *tipo;
    char *barcode;
} body_args_t;

typedef struct thread_params_t {
    body_args_t *ba;
    const char *token;
    const char *hostname;
    SSL *ssl;
    int body_len;
    int req_len;
    int n_thread;
} tparams_t;

#ifdef SCAN_LINUX

#define INVALID_FD  -1

#define RED    "\e[1;31m"
#define RESET  "\e[0m"

#define SERIAL_DIR "/dev/serial/by-id"
#define DEVNAME_LEN (256 + sizeof(SERIAL_DIR))

typedef struct open_dev_t {
    char pathname[DEVNAME_LEN];
    bool open;
} open_dev_t;

typedef open_dev_t open_devs_t[NDEVS];

#endif /* SCAN_LINUX */

#ifdef SCAN_WIN

#define COM_PORT_FORMAT "\\\\.\\COM%d"
#define N_COM 256

#endif /* SCAN_WIN */

void throw_err(const char *msg);
SSL_CTX* init_CTX();
void show_certs(SSL *ssl);