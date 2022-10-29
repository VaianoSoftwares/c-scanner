#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "scanner.h"

uint8_t coms[NDEVS];

HANDLE com_mutex, req_mutex, start_mutex;

void create_threads(HANDLE *h_threads, tparams_t *tparams);
BOOL find_serial_port(int n_thread, HANDLE h_comm);
BOOL open_serial_port(int n_thread, HANDLE h_comm, DWORD *event_mask);
BOOL read_scanner(HANDLE h_comm, DWORD dw_event_mask, char *buf, size_t size);
SOCKET conn_to_server(const char *hostname, int port);
void send_timbra_req(void *thread_params);

int main(int argc, char *argv[])
{
    printf("MAIN | Execution started.\n");

    // guest token must be specified as cmd arg
    if (argc < 2)
        throw_err("main | invalid arguments: token is missing");

    // get cmd args
    const char *token = argv[1];

    const char *hostname = (argc >= 3 && strlen(argv[2]) > 0) ? argv[2] : DEFAULT_HOSTNAME;
    int port = (argc >= 7 && atoi(argv[6]) > 0) ? atoi(argv[6]) : DEFAULT_PORT;

    body_args_t ba = { NULL };
    ba.cliente = (argc >= 4 && strlen(argv[3]) > 0) ? argv[3] : DEFAULT_CLIENTE;
    ba.postazione = (argc >= 5 && strlen(argv[4]) > 0) ? argv[4] : DEFAULT_CLIENTE;
    ba.tipo = (argc >= 6 && strlen(argv[5]) > 0) ? argv[5] : DEFAULT_TIPO;
    ba.barcode = NULL;

    int body_len = strlen(BODY_FORMAT) + strlen(ba.tipo) +
                   strlen(ba.cliente) + strlen(ba.postazione) + SCAN_BUF_SIZE;
    int req_len =
        strlen(MSG_FORMAT) + body_len + strlen(hostname) + strlen(token);

    /*#################################################################################################################*/

    // init ssl lib
    SSL_library_init();

    SSL_CTX *ctx = init_CTX();
    // connect to server
    SOCKET sock = conn_to_server(hostname, port);
    // make ssl connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) == -1)
    {
        ERR_print_errors_fp(stderr);
        throw_err("main | SSL_connect");
    }

    show_certs(ssl);

    /*#################################################################################################################*/

    // init mutexes
    com_mutex = CreateMutexW(NULL, FALSE, NULL);
    req_mutex = CreateMutexW(NULL, FALSE, NULL);
    start_mutex = CreateMutexW(NULL, FALSE, NULL);

    // params for threads
    tparams_t tparams = { NULL };
    tparams.ba = &ba;
    tparams.body_len = body_len;
    tparams.hostname = hostname;
    tparams.req_len = req_len;
    tparams.ssl = ssl;
    tparams.token = token;
    tparams.n_thread = 0;

    // init serial coms array
    memset(coms, 0, sizeof(coms));

    /*#################################################################################################################*/

    HANDLE h_threads[NDEVS] = { NULL };

    // create threads
    create_threads(h_threads, &tparams);

    printf("MAIN | Waiting for children.\n");

    // waiting for threads
    WaitForMultipleObjects(NDEVS, h_threads, TRUE, 0L);

    /*#################################################################################################################*/

    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);

    // close mutexes
    if (com_mutex)
        CloseHandle(com_mutex);
    if (req_mutex)
        CloseHandle(req_mutex);
    if(start_mutex)
        CloseHandle(start_mutex);

    printf("MAIN | Execution terminated.\n");

    return EXIT_SUCCESS;
}

void create_threads(HANDLE *h_threads, tparams_t *tparams) {
    WaitForSingleObject(start_mutex, 0L);
    // create NDEVS threads
    for (int i = 0; i < NDEVS; i++)
    {
        tparams->n_thread = i;
        h_threads[i] = (HANDLE)_beginthread(send_timbra_req, 0, (void *)tparams);
        if (!h_threads[i] || h_threads[i] == INVALID_HANDLE_VALUE)
            throw_err("main | _beginthread");
        
        printf("MAIN | Created THREAD %d.\n", i);
        WaitForSingleObject(start_mutex, INFINITE);
    }
}

void send_timbra_req(void *thread_params)
{
    // gather thread params
    tparams_t *tparams = (tparams_t *)thread_params;

    int n_thread = tparams->n_thread;
    printf("THREAD %d | Execution started.\n", n_thread);

    ReleaseMutex(start_mutex);

    body_args_t *ba = tparams->ba;

    const char *token = tparams->token;
    const char *hostname = tparams->hostname;

    SSL *ssl = tparams->ssl;

    int body_len = tparams->body_len;
    int req_len = tparams->req_len;

    /*#################################################################################################################*/

    HANDLE h_comm = INVALID_HANDLE_VALUE;
    DWORD event_mask;

    int nbytes;
    char request[req_len], response[MSG_LEN], body_msg[body_len], scan_buf[SCAN_BUF_SIZE];

    while (TRUE)
    {
        if (h_comm == INVALID_HANDLE_VALUE)
        {
            WaitForSingleObject(com_mutex, INFINITE);

            // connect scanner
            if (!open_serial_port(n_thread, h_comm, &event_mask))
            {
                fprintf(stderr, "send_timbra_req | open_serial_port\n");

                if (h_comm) CloseHandle(h_comm);
                coms[n_thread] = 0;

                ReleaseMutex(com_mutex);

                Sleep(5000);
                continue;
            }

            printf("THREAD %d | Waiting for input scanner.\n", n_thread);

            ReleaseMutex(com_mutex);
        }

        // get barcode
        if (!read_scanner(h_comm, event_mask, scan_buf, sizeof(scan_buf)))
        {
            fprintf(stderr, "send_timbra_req | read_scanner\n");
            if (h_comm) CloseHandle(h_comm);
            coms[n_thread] = 0;
            Sleep(5000);
            continue;
        }

        // create msg request
        snprintf(body_msg, sizeof(body_msg), BODY_FORMAT, scan_buf, ba->cliente, ba->postazione,
                 ba->tipo);
        snprintf(request, sizeof(request), MSG_FORMAT, hostname, token,
                 strlen(body_msg), body_msg);

        WaitForSingleObject(req_mutex, INFINITE);

        printf("---------------------------------------------------------------------------------------------------\n");
        printf("%s\n", request);
        printf("---------------------------------------------------------------------------------------------------\n");

        // send request
        if (SSL_write(ssl, request, strlen(request)) <= 0)
        {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "Unable to send request.\n");
            ReleaseMutex(req_mutex);
            break;
        }

        // recive response
        if ((nbytes = SSL_read(ssl, response, sizeof(response))) <= 0)
        {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "No response. (nbytes=%d)\n", nbytes);
            ReleaseMutex(req_mutex);
            break;
        }
        response[nbytes] = 0;

        printf("%s\n", response);

        ReleaseMutex(req_mutex);
    }

    if (h_comm) CloseHandle(h_comm);
    coms[n_thread] = 0;

    printf("THREAD %d | Execution terminated.\n", n_thread);
}

void throw_err(const char *msg)
{
    DWORD err_code = GetLastError();

    if (!err_code)
    {
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

BOOL find_serial_port(int n_thread, HANDLE h_comm)
{
    char com_port_name[16];
    BOOL port_taken = FALSE;

    for (int i = 33; i < N_COM; i++)
    {
        port_taken = FALSE;

        for (int j = 0; j < NDEVS; j++)
        {
            if (coms[j] == i)
            {
                port_taken = TRUE;
                break;
            }
        }

        if (port_taken)
            continue;

        snprintf(com_port_name, sizeof(com_port_name), COM_PORT_FORMAT, i);

        h_comm = CreateFile(
            com_port_name,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (h_comm != INVALID_HANDLE_VALUE)
        {
            coms[n_thread] = i;
            printf("THREAD %d | Found available serial device %s.\n", n_thread, com_port_name);
            return TRUE;
        }

        CloseHandle(h_comm);
    }

    fprintf(stderr, "find_serial_port | Not available serial port\n");
    return FALSE;
}

BOOL open_serial_port(int n_thread, HANDLE h_comm, DWORD *event_mask)
{
    if (!find_serial_port(n_thread, h_comm))
    {
        coms[n_thread] = 0;
        if(h_comm) CloseHandle(h_comm);
        fprintf(stderr, "open_serial_port | find_serial_port\n");
        return FALSE;
    }

    if (!FlushFileBuffers(h_comm))
    {
        coms[n_thread] = 0;
        if(h_comm) CloseHandle(h_comm);
        fprintf(stderr, "open_serial_port | FlushFileBuffer\n");
        return FALSE;
    }

    DCB dcb_serial_params = {0}; // Initializing DCB structure
    dcb_serial_params.DCBlength = sizeof(dcb_serial_params);

    if (!GetCommState(h_comm, &dcb_serial_params))
    {
        coms[n_thread] = 0;
        if(h_comm) CloseHandle(h_comm);
        fprintf(stderr, "init_scanner | GetComState\n");
        return FALSE;
    }

    dcb_serial_params.BaudRate = CBR_9600;   // Setting BaudRate = 9600
    dcb_serial_params.ByteSize = 8;          // Setting ByteSize = 8
    dcb_serial_params.StopBits = ONESTOPBIT; // Setting StopBits = 1
    dcb_serial_params.Parity = NOPARITY;     // Setting Parity = None

    if (!SetCommState(h_comm, &dcb_serial_params))
    {
        coms[n_thread] = 0;
        if(h_comm) CloseHandle(h_comm);
        fprintf(stderr, "init_scanner | SetComState\n");
        return FALSE;
    }

    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = MAXDWORD;
    timeouts.ReadTotalTimeoutConstant = 0;
    timeouts.ReadTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = 0;
    timeouts.WriteTotalTimeoutMultiplier = 0;

    if (!SetCommTimeouts(h_comm, &timeouts))
    {
        coms[n_thread] = 0;
        if(h_comm) CloseHandle(h_comm);
        fprintf(stderr, "init_scanner | SetComTimeouts\n");
        return FALSE;
    }

    *event_mask = (DWORD)EV_RXCHAR;
    if (!SetCommMask(h_comm, *event_mask))
    {
        coms[n_thread] = 0;
        if(h_comm) CloseHandle(h_comm);
        fprintf(stderr, "init_scanner | SetCommMask\n");
        return FALSE;
    }

    printf("THREAD %d | Connected serial device.\n", n_thread);

    return TRUE;
}

BOOL read_scanner(HANDLE h_comm, DWORD dw_event_mask, char *buf, size_t size)
{

    if (!WaitCommEvent(h_comm, &dw_event_mask, NULL))
    {
        fprintf(stderr, "read_scanner | WaitCommEvent");
        CloseHandle(h_comm);
        return FALSE;
    }

    char tmp_ch = 0;
    DWORD bytes_read;
    int i = 0;

    memset(buf, 0, size);

    do
    {
        if (!ReadFile(h_comm, &tmp_ch, sizeof(tmp_ch), &bytes_read, NULL))
        {
            fprintf(stderr, "read_scanner | ReadFile");
            CloseHandle(h_comm);
            return FALSE;
        }

        if (bytes_read)
            buf[i++] = tmp_ch;
    } while (bytes_read);

    return TRUE;
}

SOCKET conn_to_server(const char *hostname, int port)
{
    WSADATA wsa;
    SOCKET sock;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != NO_ERROR)
    {
        fprintf(stderr, "Failed. Error Code : %d.\n", WSAGetLastError());
        throw_err("conn_to_server | WSAStartup");
    }

    // Create a socket
    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
    {
        fprintf(stderr, "Could not create socket : %d.\n", WSAGetLastError());
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
    do
    {
        // connect to server
        // if connection failed retry to connect after 1 sec
        if ((connected = connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) == SOCKET_ERROR)
        {
            fprintf(stderr, "Connection to server failed. Error: %d\n", WSAGetLastError());
            Sleep(1000);
        }
    } while (connected == SOCKET_ERROR);

    printf("Connection to %s:%d enstablished.\n", hostname, port);

    return sock;
}

SSL_CTX *init_CTX()
{
    OpenSSL_add_all_algorithms(); /* Load cryptos, et.al. */
    SSL_load_error_strings();     /* Bring in and register error messages */

    const SSL_METHOD *method = TLS_client_method(); /* Create new client-method instance */
    SSL_CTX *ctx = SSL_CTX_new(method);             /* Create new context */
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        throw_err("init_CTX | SSL_CTX_new");
    }

    return ctx;
}

void show_certs(SSL *ssl)
{
    char *line;

    X509 *cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert == NULL)
    {
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