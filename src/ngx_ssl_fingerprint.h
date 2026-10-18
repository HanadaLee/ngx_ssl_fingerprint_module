/*
 * Copyright (C) 2020-2024 Phus Lu
 * Copyright (C) Hanada
 */


#ifndef _NGX_SSL_FINGERPRINT_H_INCLUDED_
#define _NGX_SSL_FINGERPRINT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


enum {
    NGX_SSL_FP_GREASED,
    NGX_SSL_FP_JA3,
    NGX_SSL_FP_JA3_HASH,
    NGX_SSL_FP_JA4_R,
    NGX_SSL_FP_JA4,
    NGX_SSL_FP_JA4_RO,
    NGX_SSL_FP_JA4_O,
    NGX_SSL_FP_VARIABLES
};


extern ngx_uint_t    ngx_ssl_fingerprint_enabled;
extern ngx_cycle_t  *ngx_ssl_fingerprint_cycle;

void ngx_ssl_fingerprint_message(int write_p, int version, int content_type,
    const void *buf, size_t len, ngx_ssl_conn_t *ssl, void *arg);
ngx_int_t ngx_ssl_fingerprint_variable(ngx_connection_t *c, ngx_uint_t index,
    ngx_str_t *value);


#endif /* _NGX_SSL_FINGERPRINT_H_INCLUDED_ */

