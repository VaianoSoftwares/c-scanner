#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// #pragma comment(lib,"ws2_32.lib")
// #pragma comment(lib,"ssl.lib")
// #pragma comment(lib,"crypto.lib")

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

#define SCAN_BUF_SIZE 32
#define COM_PORT_FORMAT "\\\\.\\COM%d"
#define N_COM 256

void throw_err(const char *msg);
HANDLE open_serial_port(DWORD *dw_event_mask);
void read_scanner(HANDLE h_comm, DWORD dw_event_mask, char *buf, size_t size);
SOCKET conn_to_server(const char *hostname, int port);
SSL_CTX* init_CTX();
void show_certs(SSL *ssl);

int main(int argc, char *argv[]) {
    if(argc < 2) throw_err("main | invalid arguments: token is missing");

    SSL_library_init();

    // get cmd args
    const char *hostname = (argc >= 3 && strlen(argv[2]) > 0) ? argv[2] : DEFAULT_HOSTNAME;
    int port = (argc >= 7 && atoi(argv[6]) > 0) ? atoi(argv[6]) : DEFAULT_PORT;

    const char *body_args[3];
    body_args[0] = (argc >= 4 && strlen(argv[3]) > 0) ? argv[3] : DEFAULT_CLIENTE;
    body_args[1] = (argc >= 5 && strlen(argv[4]) > 0) ? argv[4] : DEFAULT_POST;
    body_args[2] = (argc >= 6 && strlen(argv[5]) > 0) ? argv[5] : DEFAULT_TIPO;

    // connect scanner
    DWORD dw_event_mask;
    HANDLE h_comm = open_serial_port(&dw_event_mask);

    SSL_CTX *ctx = init_CTX();
    // connect to server
    SOCKET sock = conn_to_server(hostname, port);
    // make ssl connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if(SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
        throw_err("main | SSL_connect");
    }

    show_certs(ssl);

    int nbytes;

    int body_len = strlen(BODY_FORMAT) + strlen(body_args[0]) +
                   strlen(body_args[1]) + strlen(body_args[2]) + SCAN_BUF_SIZE;
    int msg_len =
        strlen(MSG_FORMAT) + body_len + strlen(hostname) + strlen(argv[1]);
    
    char request[msg_len], response[MSG_LEN], body_msg[body_len], scan_buf[SCAN_BUF_SIZE];

    printf("Waiting for scanner input.\n");

    while(TRUE) {
        // get barcode
        read_scanner(h_comm, dw_event_mask, scan_buf, sizeof(scan_buf));

        // create msg request
        snprintf(body_msg, sizeof(body_msg), BODY_FORMAT, scan_buf, body_args[0], body_args[1],
                 body_args[2]);
        snprintf(request, sizeof(request), MSG_FORMAT, hostname, argv[1],
                 strlen(body_msg), body_msg);

        printf("---------------------------------------------------------------------------------------------------\n");
        printf("%s\n", request);
        printf("---------------------------------------------------------------------------------------------------\n");

        // send request
        if(SSL_write(ssl, request, strlen(request)) <= 0) {
            fprintf(stderr, "Unable to send request.\n");
            continue;
        }

        // recive response
        if((nbytes = SSL_read(ssl, response, sizeof(response))) <= 0) {
            fprintf(stderr, "No response. (nbytes=%d)\n", nbytes);
            continue;
        }
        response[nbytes] = 0;

        printf("%s\n", response);
    }

    CloseHandle(h_comm);
    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);

    return EXIT_SUCCESS;
}

void throw_err(const char *msg) {
    DWORD err_code = GetLastError();

    if(!err_code) {
        fprintf(stderr, "%s", msg);
        exit(EXIT_FAILURE);
    }

    LPTSTR lpMsgBuf;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, err_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR)&lpMsgBuf, 0, NULL);

    fprintf(stderr, "%s: %s", msg, lpMsgBuf);

    LocalFree(lpMsgBuf);
    exit(err_code);
}

HANDLE find_serial_port() {
    HANDLE h_comm;

    char com_port_name[16];
    BOOL found = FALSE;

    for(int i=33; i<N_COM; i++) {
        snprintf(com_port_name, sizeof(com_port_name), COM_PORT_FORMAT, i);

        h_comm = CreateFile(
            com_port_name,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,                        
            OPEN_EXISTING,                
            FILE_ATTRIBUTE_NORMAL,                            
            NULL
        );

        if(h_comm != INVALID_HANDLE_VALUE) {
            found = TRUE;
            break;
        }
    }

    if(!found) throw_err("find_serial_port | Not available serial port");

    printf("Connected to %s.\n", com_port_name);

    return h_comm;
}

HANDLE open_serial_port(DWORD *dw_event_mask) {
    HANDLE h_comm = find_serial_port();

    if(!FlushFileBuffers(h_comm)) {
        CloseHandle(h_comm);
        throw_err("open_serial_port | FlushFileBuffer");
    }
    
    DCB dcb_serial_params = {0};             // Initializing DCB structure
    dcb_serial_params.DCBlength = sizeof(dcb_serial_params);

    if(!GetCommState(h_comm, &dcb_serial_params)) {
        CloseHandle(h_comm);
        throw_err("init_scanner | GetComState");
    }

    dcb_serial_params.BaudRate = CBR_9600;      // Setting BaudRate = 9600
    dcb_serial_params.ByteSize = 8;             // Setting ByteSize = 8
    dcb_serial_params.StopBits = ONESTOPBIT;    // Setting StopBits = 1
    dcb_serial_params.Parity = NOPARITY;        // Setting Parity = None 

    if(!SetCommState(h_comm, &dcb_serial_params)) {
        CloseHandle(h_comm);
        throw_err("init_scanner | SetComState");
    }
    
    COMMTIMEOUTS timeouts = { 0 };
    timeouts.ReadIntervalTimeout         = MAXDWORD;
    timeouts.ReadTotalTimeoutConstant    = 0;
    timeouts.ReadTotalTimeoutMultiplier  = 0;
    timeouts.WriteTotalTimeoutConstant   = 0;
    timeouts.WriteTotalTimeoutMultiplier = 0;
        
    if(!SetCommTimeouts(h_comm, &timeouts)) {
        CloseHandle(h_comm);
        throw_err("init_scanner | SetComTimeouts");
    }

    *dw_event_mask = (DWORD)EV_RXCHAR;
    if(!SetCommMask(h_comm, *dw_event_mask)) {
        CloseHandle(h_comm);
        throw_err("init_scanner | SetCommMask");
    }

    printf("Finished serial device setup.\n");
    
    return h_comm;
}

void read_scanner(HANDLE h_comm, DWORD dw_event_mask, char *buf, size_t size) {
    char tmp_ch = 0;
    DWORD bytes_read;
    int i = 0;

    if(!WaitCommEvent(h_comm, &dw_event_mask, NULL))
            throw_err("read_scanner | WaitCommEvent");

    memset(buf, 0, size);

    do {
        if(!ReadFile(h_comm, &tmp_ch, sizeof(tmp_ch), &bytes_read, NULL))
            throw_err("read_scanner | ReadFile");

        if(bytes_read) buf[i++] = tmp_ch;
    } while(bytes_read);
}

SOCKET conn_to_server(const char *hostname, int port) {
    WSADATA wsa;
    SOCKET sock;

    if(WSAStartup(MAKEWORD(2,2), &wsa) != NO_ERROR) {
        printf("Failed. Error Code : %d.\nPress a key to exit...", WSAGetLastError());
        throw_err("conn_to_server | WSAStartup");
    }

    //Create a socket
    if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
        printf("Could not create socket : %d.\n", WSAGetLastError());
        WSACleanup();
        throw_err("conn_to_server | socket");
    }
    
    // set socket options
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_addr.s_addr = inet_addr(hostname);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    printf("Attempt connection to %s:%d.\n", hostname, port);

    // loop while connection is not enstablished
    int connected;
    do {
        // connect to server
        // if connection failed retry to connect after 1 sec
        if((connected = connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) == SOCKET_ERROR) {
            printf("Connection to server failed. Error: %d\n", WSAGetLastError());
            Sleep(1);
        }
    } while(connected == SOCKET_ERROR);

    printf("Connection to %s:%d enstablished.\n", hostname, port);

    return sock;
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