
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pem.h>

#define CA_LIST "/data/conf/etc/ssl/certs/ca-certificates.crt"

extern const unsigned char _etc_ssl_certs_ca_certificates_crt[];
extern const unsigned int _etc_ssl_certs_ca_certificates_crt_len;

void print(const char *format, ...)
{
    static unsigned long start_time = 0;
    va_list argptr;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long time_in_micros = 1000000 * tv.tv_sec + tv.tv_usec;

    if (start_time == 0)
    {
        start_time = time_in_micros;
    }

    time_in_micros -= start_time;

    fprintf(stderr, "[%10lu] ", time_in_micros);
    va_start(argptr, format);
    vfprintf(stderr, format, argptr);
    va_end(argptr);
}

int main(int argc, char *argv[])
{
    mbedtls_x509_crt *crt = NULL;
    // unsigned char *buf = NULL;
    print("Hello!\n");
    int ret = 0;

    mbedtls_debug_set_threshold(5);

#if 0
    FILE *fp = fopen(CA_LIST, "rb");
    if (!fp)
    {
        print("Failed: fopen %d\n", errno);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long buflen = ftell(fp);
    print("File length is %ld\n", buflen);

    buf = malloc(buflen + 1);
    if (!buf)
    {
        print("Failed: malloc buf %d\n", errno);
        ret = 1;
        goto end;
    }

    rewind(fp);

    print("Start read\n");

    if (fread(buf, buflen, 1, fp) != 1)
    {
        print("Failed: fread %d\n", errno);
        ret = 1;
        goto end;
    }
    print("End read\n");

    buf[buflen] = '\0';
#endif

    unsigned char *buf = _etc_ssl_certs_ca_certificates_crt;

    long buflen = _etc_ssl_certs_ca_certificates_crt_len;

    if ((crt = malloc(sizeof(*crt))) == NULL)
    {
        print("Failed: malloc crt %d\n", errno);
        ret = 1;
        goto end;
    }

    for (unsigned long i = 0; i < 500; i++)
    {
        fputc(buf[i], stderr);
    }

    fprintf(stderr, "\n...\n");
    for (unsigned long i = buflen - 500; i < buflen; i++)
    {
        fputc(buf[i], stderr);
    }

    int rv;
#if 0
    print("Start parse\n");
    mbedtls_x509_crt_init(crt);
    rv = mbedtls_x509_crt_parse(crt, buf, buflen);

    if (rv != 0)
    {
        print("Failed: mbedtls_x509_crt_parse %d\n", rv);
        ret = 1;
        goto end;
    }
    print("End parse\n");
#endif

    mbedtls_pem_context pem;

    while (buflen > 1)
    {
        size_t use_len;
        mbedtls_pem_init(&pem);
        ret = mbedtls_pem_read_buffer(&pem,
                                      "-----BEGIN CERTIFICATE-----",
                                      "-----END CERTIFICATE-----",
                                      buf, NULL, 0, &use_len);
        if (ret == 0)
        {
            /*
             * Was PEM encoded
             */
            buflen -= use_len;
            buf += use_len;
            fprintf(stderr, "good\n");
        }
        else if (ret == MBEDTLS_ERR_PEM_BAD_INPUT_DATA)
        {
            fprintf(stderr, "bad input data\n");
            goto end;
        }
        else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT)
        {
            fprintf(stderr, "no footer present\n");
            goto end;
        }
        else
        {
            fprintf(stderr, "another error\n");
            goto end;
        }

        fflush(stderr);
        ret = mbedtls_x509_crt_parse_der(crt, pem.buf, pem.buflen);

        mbedtls_pem_free(&pem);
    }

#if 1
    int fd = (int)socket(AF_INET, SOCK_STREAM,
                         IPPROTO_TCP);
    if (fd < 0)
    {
        ret = 1;
        goto end;
    }

    struct sockaddr_in adr_inet;

    memset(&adr_inet, 0, sizeof adr_inet);

    adr_inet.sin_family = AF_INET;
    adr_inet.sin_port = htons(443);

    adr_inet.sin_addr.s_addr = inet_addr("18.160.46.55");
    print("Start connect (socket)\n");
    if (connect(fd, (struct sockaddr *)&adr_inet, sizeof adr_inet) != 0)
    {
        print("error connect %d (socket)\n", errno);

        ret = 1;
        goto end;
    }

    print("End connect (socket)\n");
    print("Start close (socket)\n");
    close(fd);
    print("End close (socket)\n");
#endif

#if 0
    mbedtls_net_context server_fd;
    print("Start connect\n");

    mbedtls_net_init(&server_fd);
    if ((rv = mbedtls_net_connect(&server_fd,
                                  "18.160.46.55", "443",
                                  MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        print("Failed: mbedtls_net_connect returned -0x%x\n",
              (unsigned int)-rv);
        ret = 1;
        goto end;
    }
    print("End connect\n");
#endif
end:
    // if (fclose(fp))
    // {
    //     print("Failed: fclose %d\n", errno);
    // }

    free(crt);
    // free(buf);

    return ret;
}
