
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_ssl_fingerprint.h>


static ngx_int_t ngx_http_ssl_fingerprint_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_ssl_greased(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_fingerprint_ja3(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_fingerprint_ja3_hash(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_http2_fingerprint(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_fingerprint_ja4_r(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_fingerprint_ja4(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_fingerprint_ja4_ro(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_fingerprint_ja4_o(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_http_module_t  ngx_http_ssl_fingerprint_module_ctx = {
    ngx_http_ssl_fingerprint_add_variables,  /* preconfiguration */
    NULL,                                    /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */

    NULL,                                    /* create location configuration */
    NULL                                     /* merge location configuration */
};


ngx_module_t  ngx_http_ssl_fingerprint_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_fingerprint_module_ctx,    /* module context */
    NULL,                                    /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_ssl_fingerprint_vars[] = {

    { ngx_string("ssl_greased"), NULL,
      ngx_http_ssl_greased,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_fingerprint_ja3"), NULL,
      ngx_http_ssl_fingerprint_ja3,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_fingerprint_ja3_hash"), NULL,
      ngx_http_ssl_fingerprint_ja3_hash,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("http2_fingerprint"), NULL,
      ngx_http_http2_fingerprint,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_fingerprint_ja4_r"), NULL,
      ngx_http_ssl_fingerprint_ja4_r,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_fingerprint_ja4"), NULL,
      ngx_http_ssl_fingerprint_ja4,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_fingerprint_ja4_ro"), NULL,
      ngx_http_ssl_fingerprint_ja4_ro,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_fingerprint_ja4_o"), NULL,
      ngx_http_ssl_fingerprint_ja4_o,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_ssl_greased(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    if (r->connection->ssl == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja3(r->connection) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    v->len = 1;
    v->data = (u_char*) (r->connection->ssl->fp_tls_greased ? "1" : "0");
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_fingerprint_ja3(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{

    if (r->connection->ssl == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja3(r->connection) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    v->data = r->connection->ssl->fp_ja3_str.data;
    v->len = r->connection->ssl->fp_ja3_str.len;
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_fingerprint_ja3_hash(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->connection->ssl == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja3_hash(r->connection) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = r->connection->ssl->fp_ja3_hash.data;
    v->len = r->connection->ssl->fp_ja3_hash.len;
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_http2_fingerprint(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    if (r->stream == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_http2_fingerprint(r->connection, r->stream->connection)
            != NGX_OK)
    {
        v->not_found = 1;
        return NGX_ERROR;
    }

    v->data = r->stream->connection->fp_str.data;
    v->len = r->stream->connection->fp_str.len;
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_fingerprint_ja4_r(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->connection->ssl == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja4_r(r->connection) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    v->data = r->connection->ssl->fp_ja4_r.data;
    v->len = r->connection->ssl->fp_ja4_r.len;

#if (NGX_QUIC)
    if (r->connection->quic && v->len > 0) {
        v->data[0] = 'q';
    }
#endif

    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_fingerprint_ja4(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->connection->ssl == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja4(r->connection) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = r->connection->ssl->fp_ja4.data;
    v->len = r->connection->ssl->fp_ja4.len;

#if (NGX_QUIC)
    if (r->connection->quic && v->len > 0) {
        v->data[0] = 'q';
    }
#endif

    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_fingerprint_ja4_ro(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    if (r->connection->ssl == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja4_ro(r->connection) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    v->data = r->connection->ssl->fp_ja4_ro.data;
    v->len = r->connection->ssl->fp_ja4_ro.len;

#if (NGX_QUIC)
    if (r->connection->quic && v->len > 0) {
        v->data[0] = 'q';
    }
#endif

    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_fingerprint_ja4_o(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->connection->ssl == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja4_o(r->connection) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = r->connection->ssl->fp_ja4_o.data;
    v->len = r->connection->ssl->fp_ja4_o.len;

#if (NGX_QUIC)
    if (r->connection->quic && v->len > 0) {
        v->data[0] = 'q';
    }
#endif

    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_fingerprint_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_ssl_fingerprint_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}
