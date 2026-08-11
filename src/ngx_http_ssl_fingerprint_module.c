
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_ssl_fingerprint.h>


typedef struct {
    ngx_flag_t  enabled;
} ngx_http_ssl_fingerprint_main_conf_t;


static ngx_int_t ngx_http_ssl_fingerprint_add_variables(ngx_conf_t *cf);
static void *ngx_http_ssl_fingerprint_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_ssl_fingerprint_init_main_conf(ngx_conf_t *cf,
    void *conf);
static ngx_int_t ngx_http_ssl_fingerprint_is_available(ngx_http_request_t *r);
static ngx_int_t ngx_http_ssl_greased(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_fingerprint_ja3(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_fingerprint_ja3_hash(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_fingerprint_ja4_r(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_fingerprint_ja4(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_fingerprint_ja4_ro(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_fingerprint_ja4_o(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_command_t  ngx_http_ssl_fingerprint_commands[] = {

    { ngx_string("ssl_fingerprint"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_ssl_fingerprint_main_conf_t, enabled),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ssl_fingerprint_module_ctx = {
    ngx_http_ssl_fingerprint_add_variables,    /* preconfiguration */
    NULL,                                      /* postconfiguration */

    ngx_http_ssl_fingerprint_create_main_conf, /* create main conf */
    ngx_http_ssl_fingerprint_init_main_conf,   /* init main conf */

    NULL,                                      /* create server conf */
    NULL,                                      /* merge server conf */

    NULL,                                      /* create location conf */
    NULL                                       /* merge location conf */
};


ngx_module_t  ngx_http_ssl_fingerprint_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_fingerprint_module_ctx,      /* module context */
    ngx_http_ssl_fingerprint_commands,         /* module directives */
    NGX_HTTP_MODULE,                           /* module type */
    NULL,                                      /* init master */
    NULL,                                      /* init module */
    NULL,                                      /* init process */
    NULL,                                      /* init thread */
    NULL,                                      /* exit thread */
    NULL,                                      /* exit process */
    NULL,                                      /* exit master */
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
    if (ngx_http_ssl_fingerprint_is_available(r) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja3(r->connection) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    v->len = 1;
    v->data = (u_char *) (r->connection->ssl->fp_greased ? "1" : "0");
    v->not_found = 0;
    v->valid = 1;
    v->no_cacheable = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_fingerprint_ja3(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{

    if (ngx_http_ssl_fingerprint_is_available(r) != NGX_OK) {
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
    if (ngx_http_ssl_fingerprint_is_available(r) != NGX_OK) {
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
ngx_http_ssl_fingerprint_ja4_r(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (ngx_http_ssl_fingerprint_is_available(r) != NGX_OK) {
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
    if (ngx_http_ssl_fingerprint_is_available(r) != NGX_OK) {
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

    if (ngx_http_ssl_fingerprint_is_available(r) != NGX_OK) {
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
    if (ngx_http_ssl_fingerprint_is_available(r) != NGX_OK) {
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


static void *
ngx_http_ssl_fingerprint_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_ssl_fingerprint_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssl_fingerprint_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_ssl_fingerprint_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_ssl_fingerprint_main_conf_t  *smcf = conf;

    if (ngx_ssl_fingerprint_cycle != cf->cycle) {
        ngx_ssl_fingerprint_cycle = cf->cycle;
        ngx_ssl_fingerprint_enabled = 0;
    }

    if (smcf->enabled != NGX_CONF_UNSET) {
        ngx_ssl_fingerprint_enabled = smcf->enabled;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_ssl_fingerprint_is_available(ngx_http_request_t *r)
{
    if (!ngx_ssl_fingerprint_enabled) {
        return NGX_DECLINED;
    }

    if (r->connection->ssl == NULL) {
        return NGX_DECLINED;
    }

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
