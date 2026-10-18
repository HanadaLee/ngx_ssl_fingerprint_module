/*
 * Copyright (C) Hanada
 */


#ifndef _NGX_TEST_CORE_H_INCLUDED_
#define _NGX_TEST_CORE_H_INCLUDED_


#include <ngx_config.h>


typedef uintptr_t  ngx_uint_t;
typedef intptr_t   ngx_int_t;
typedef intptr_t   ngx_flag_t;
typedef void       ngx_cycle_t;
typedef SSL  ngx_ssl_conn_t;


typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;


typedef struct {
    void    *allocs[32];
    size_t   n;
    size_t   bytes;
} ngx_pool_t;


typedef struct {
    SSL       *connection;
    void      *fp_ctx;
    unsigned   fp_collected:1;
} ngx_ssl_connection_t;


typedef struct {
    ngx_ssl_connection_t  *ssl;
    ngx_pool_t            *pool;
    void                  *log;
    void                  *quic;
    int                    type;
} ngx_connection_t;


#define NGX_OK         0
#define NGX_ERROR     -1
#define NGX_DECLINED  -5
#define NGX_QUIC       1

#define ngx_min(a, b)             ((a) < (b) ? (a) : (b))
#define ngx_max(a, b)             ((a) > (b) ? (a) : (b))
#define ngx_qsort                 qsort
#define ngx_memcpy(dst, src, n)   memcpy((dst), (src), (n))
#define ngx_memset(buf, c, n)     memset((buf), (c), (n))
#define ngx_memzero(buf, n)       memset((buf), 0, (n))
#define ngx_cpymem(dst, src, n)   (((u_char *) memcpy((dst), (src), (n))) + (n))
#define ngx_str_null(str)         ((str)->len = 0, (str)->data = NULL)
#define ngx_log_debug0(...)       ((void) 0)
#define ngx_ssl_get_connection(s) ((ngx_connection_t *) SSL_get_app_data(s))


static int     ngx_test_pool_fail = -1;
static int     ngx_test_heap_fail = -1;
static size_t  ngx_test_heap_live;


static void *
ngx_alloc(size_t n, void *log)
{
    void  *p;

    (void) log;

    if (ngx_test_heap_fail == 0) {
        return NULL;
    }

    if (ngx_test_heap_fail > 0) {
        ngx_test_heap_fail--;
    }

    p = malloc(n ? n : 1);
    if (p != NULL) {
        ngx_test_heap_live++;
    }

    return p;
}


static void
ngx_free(void *p)
{
    if (p != NULL) {
        ngx_test_heap_live--;
        free(p);
    }
}


static void *
ngx_palloc(ngx_pool_t *pool, size_t n)
{
    void  *p;

    if (ngx_test_pool_fail == 0) {
        return NULL;
    }

    if (ngx_test_pool_fail > 0) {
        ngx_test_pool_fail--;
    }

    p = malloc(n ? n : 1);
    if (p != NULL) {
        if (pool->n == 32) {
            abort();
        }

        memset(p, 0xcc, n);
        pool->allocs[pool->n++] = p;
        pool->bytes += n;
    }

    return p;
}


#define ngx_pnalloc  ngx_palloc


static void
ngx_destroy_pool(ngx_pool_t *pool)
{
    while (pool->n) {
        free(pool->allocs[--pool->n]);
    }
}


static u_char *
ngx_hex_dump(u_char *p, const u_char *data, size_t n)
{
    static const char  hex[] = "0123456789abcdef";

    while (n--) {
        *p++ = hex[*data >> 4];
        *p++ = hex[*data++ & 15];
    }

    return p;
}


#endif /* _NGX_TEST_CORE_H_INCLUDED_ */
