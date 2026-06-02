
/*
 * Obj: ngx_ssl_fingerprint.c
 */

#ifndef NGX_SSL_FINGERPRINT_H_
#define NGX_SSL_FINGERPRINT_H_ 1


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


extern ngx_uint_t     ngx_ssl_fingerprint_enabled;
extern ngx_cycle_t   *ngx_ssl_fingerprint_cycle;


int ngx_ssl_fingerprint_ja3(ngx_connection_t *c);
int ngx_ssl_fingerprint_ja3_hash(ngx_connection_t *c);
int ngx_ssl_fingerprint_ja4_r(ngx_connection_t *c);
int ngx_ssl_fingerprint_ja4(ngx_connection_t *c);
int ngx_ssl_fingerprint_ja4_ro(ngx_connection_t *c);
int ngx_ssl_fingerprint_ja4_o(ngx_connection_t *c);


#endif /** NGX_SSL_FINGERPRINT_H_ */

