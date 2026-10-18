/*
 * Copyright (C) Hanada
 */


/* Exercise the production implementation with allocation-sized ASan guards. */

#include <ngx_config.h>
#include <ngx_core.h>


static int  ngx_test_digest_failure;


static EVP_MD_CTX *
ngx_test_ctx_new(void)
{
    return ngx_test_digest_failure == 1 ? NULL : EVP_MD_CTX_new();
}


static int
ngx_test_init(EVP_MD_CTX *ctx, const EVP_MD *md, ENGINE *engine)
{
    return ngx_test_digest_failure == 2 ? 0
                                       : EVP_DigestInit_ex(ctx, md, engine);
}


static int
ngx_test_update(EVP_MD_CTX *ctx, const void *p, size_t n)
{
    return ngx_test_digest_failure == 3 ? 0 : EVP_DigestUpdate(ctx, p, n);
}


static int
ngx_test_final(EVP_MD_CTX *ctx, unsigned char *p, unsigned int *n)
{
    return ngx_test_digest_failure == 4 ? 0 : EVP_DigestFinal_ex(ctx, p, n);
}


/* These aliases inject failures into the external OpenSSL API. */
#define EVP_MD_CTX_new       ngx_test_ctx_new
#define EVP_DigestInit_ex    ngx_test_init
#define EVP_DigestUpdate     ngx_test_update
#define EVP_DigestFinal_ex   ngx_test_final

#include "../../src/ngx_ssl_fingerprint.c"


int
main(void)
{
    int                     first, clean, lazy, stable;
    char                   *line, *hex;
    u_char                 *bytes;
    size_t                  cap, len, i, snapshot;
    SSL_CTX                *context;
    ngx_int_t               rc;
    ngx_str_t               value, again;
    ngx_pool_t              pool, stream_pool;
    unsigned int            x;
    ngx_connection_t        owner, stream, *c;
    ngx_ssl_connection_t    state;
    ngx_ssl_fingerprint_t  *fp;

    line = NULL;
    cap = 0;
    context = SSL_CTX_new(TLS_method());
    if (context == NULL) {
        return 2;
    }

    while (getline(&line, &cap, stdin) > 0) {
        hex = strchr(line, ' ');
        if (hex == NULL) {
            return 3;
        }

        *hex++ = 0;
        len = strcspn(hex, "\r\n") / 2;
        bytes = malloc(len + 1);
        if (bytes == NULL) {
            return 8;
        }

        for (i = 0; i < len; i++) {
            if (sscanf(hex + 2 * i, "%2x", &x) != 1) {
                return 4;
            }

            bytes[i] = (u_char) x;
        }

        ngx_memzero(&pool, sizeof(pool));
        ngx_memzero(&stream_pool, sizeof(stream_pool));
        ngx_memzero(&state, sizeof(state));
        ngx_memzero(&owner, sizeof(owner));
        ngx_memzero(&stream, sizeof(stream));

        owner.ssl = &state;
        owner.pool = &pool;
        stream.ssl = &state;
        stream.pool = &stream_pool;
        c = strcmp(line, "http3") == 0 ? &stream : &owner;

        state.connection = SSL_new(context);
        if (state.connection == NULL) {
            return 5;
        }

        SSL_set_app_data(state.connection, &owner);

        if (strcmp(line, "http3") == 0) {
            owner.type = SOCK_DGRAM;
        }

        ngx_ssl_fingerprint_enabled = strcmp(line, "disabled") != 0;

        if (strcmp(line, "capture_oom") == 0) {
            ngx_test_pool_fail = 0;
        }

        if (strcmp(line, "noise") == 0) {
            ngx_ssl_fingerprint_message(1, 0, SSL3_RT_HANDSHAKE, bytes, len,
                                        state.connection, NULL);
            ngx_ssl_fingerprint_message(0, 0, SSL3_RT_APPLICATION_DATA,
                                        bytes, len, state.connection, NULL);
            if (state.fp_collected) {
                return 6;
            }
        }

        ngx_ssl_fingerprint_message(0, 0, SSL3_RT_HANDSHAKE, bytes, len,
                                    state.connection, NULL);
        ngx_test_pool_fail = -1;
        snapshot = pool.bytes;
        fp = state.fp_ctx;
        first = 0;
        clean = 1;

        if (fp != NULL
            && (strncmp(line, "digest", 6) == 0
                || strcmp(line, "output_oom") == 0
                || strcmp(line, "heap_oom") == 0))
        {
            if (strncmp(line, "digest", 6) == 0) {
                ngx_test_digest_failure = atoi(line + 6);
            }

            if (strcmp(line, "output_oom") == 0) {
                ngx_test_pool_fail = 0;
            }

            if (strcmp(line, "heap_oom") == 0) {
                ngx_test_heap_fail = 0;
            }

            first = ngx_ssl_fingerprint_variable(c, NGX_SSL_FP_JA4, &value);
            clean = fp->values[NGX_SSL_FP_JA4].data == NULL
                    && fp->values[NGX_SSL_FP_JA4].len == 0;
            ngx_test_digest_failure = 0;
            ngx_test_pool_fail = -1;
            ngx_test_heap_fail = -1;
        }

        if (fp != NULL && strcmp(line, "replay") == 0) {
            bytes[4] ^= 1;
            ngx_ssl_fingerprint_message(0, 0, SSL3_RT_HANDSHAKE, bytes, len,
                                        state.connection, NULL);
            if (state.fp_ctx != fp || pool.bytes != snapshot) {
                return 7;
            }
        }

        lazy = 1;

        if (fp != NULL) {
            ngx_ssl_fingerprint_variable(c, NGX_SSL_FP_JA3_HASH, &value);
            ngx_ssl_fingerprint_variable(c, NGX_SSL_FP_JA4, &value);
            ngx_ssl_fingerprint_variable(c, NGX_SSL_FP_JA4_O, &value);
            lazy = fp->values[NGX_SSL_FP_JA3].data == NULL
                   && fp->values[NGX_SSL_FP_JA4_R].data == NULL
                   && fp->values[NGX_SSL_FP_JA4_RO].data == NULL;
        }

        printf("{\"snapshot\":%zu,\"first\":%d,\"clean\":%d,\"lazy\":%d,"
               "\"values\":[", snapshot, first, clean, lazy);

        for (i = 0; i < NGX_SSL_FP_VARIABLES; i++) {
            rc = ngx_ssl_fingerprint_variable(c, i, &value);
            if (i) {
                putchar(',');
            }

            if (rc == NGX_OK) {
                printf("\"%.*s\"", (int) value.len, value.data);

            } else {
                printf("null");
            }
        }

        ngx_destroy_pool(&stream_pool);
        stable = 1;

        if (fp != NULL) {
            for (i = 0; i < NGX_SSL_FP_VARIABLES; i++) {
                if (ngx_ssl_fingerprint_variable(&owner, i, &again) != NGX_OK) {
                    stable = 0;

                } else if (i != NGX_SSL_FP_GREASED
                           && again.data != fp->values[i].data)
                {
                    stable = 0;
                }
            }
        }

        printf("],\"stable\":%d,\"heap_live\":%zu}\n",
               stable, ngx_test_heap_live);
        ngx_destroy_pool(&pool);
        SSL_free(state.connection);
        free(bytes);
    }

    free(line);
    SSL_CTX_free(context);

    return 0;
}
