
/*
 * Obj: ngx_ssl_fingerprint.c
 */

#ifndef NGX_SSL_FINGERPRINT_H_
#define NGX_SSL_FINGERPRINT_H_ 1


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

int ngx_ssl_fingerprint_ja3(ngx_connection_t *c);
int ngx_ssl_fingerprint_ja3_hash(ngx_connection_t *c);
int ngx_http2_fingerprint(ngx_connection_t *c, ngx_http_v2_connection_t *h2c);
int ngx_ssl_fingerprint_ja4_r(ngx_connection_t *c);
int ngx_ssl_fingerprint_ja4(ngx_connection_t *c);
int ngx_ssl_fingerprint_ja4_ro(ngx_connection_t *c);
int ngx_ssl_fingerprint_ja4_o(ngx_connection_t *c);

#endif /** NGX_SSL_FINGERPRINT_H_ */

