
/*
 * Please make sure that you have been incuded --with-stream_ssl_module
 * before --add-module else this module won't be compiled
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_md5.h>


extern int ngx_ssl_fingerprint_ja3(ngx_connection_t *c);
extern int ngx_ssl_fingerprint_ja3_hash(ngx_connection_t *c);
extern int ngx_ssl_fingerprint_ja4_r(ngx_connection_t *c);
extern int ngx_ssl_fingerprint_ja4(ngx_connection_t *c);
extern int ngx_ssl_fingerprint_ja4_ro(ngx_connection_t *c);
extern int ngx_ssl_fingerprint_ja4_o(ngx_connection_t *c);
extern ngx_uint_t ngx_ssl_fingerprint_enabled;
extern ngx_cycle_t *ngx_ssl_fingerprint_cycle;


typedef struct {
    ngx_flag_t  enabled;
} ngx_stream_ssl_fingerprint_main_conf_t;


static ngx_int_t ngx_stream_ssl_fingerprint_add_variables(ngx_conf_t *cf);
static void *ngx_stream_ssl_fingerprint_create_main_conf(ngx_conf_t *cf);
static char *ngx_stream_ssl_fingerprint_init_main_conf(ngx_conf_t *cf,
    void *conf);
static ngx_int_t ngx_stream_ssl_fingerprint_is_available(
    ngx_stream_session_t *s);
static ngx_int_t ngx_stream_ssl_greased(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_fingerprint_ja3(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_fingerprint_ja3_hash(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_fingerprint_ja4_r(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_fingerprint_ja4(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_fingerprint_ja4_ro(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_fingerprint_ja4_o(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);


static ngx_command_t  ngx_stream_ssl_fingerprint_commands[] = {

    { ngx_string("ssl_fingerprint"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_MAIN_CONF_OFFSET,
      offsetof(ngx_stream_ssl_fingerprint_main_conf_t, enabled),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_ssl_fingerprint_module_ctx = {
    NULL,                                                /* preconfiguration */
    ngx_stream_ssl_fingerprint_add_variables,            /* postconfiguration */

    ngx_stream_ssl_fingerprint_create_main_conf,         /* create main conf */
    ngx_stream_ssl_fingerprint_init_main_conf,           /* init main conf */

    NULL,                                                /* create srv conf */
    NULL                                                 /* merge srv conf */
};


ngx_module_t  ngx_stream_ssl_fingerprint_module = {
    NGX_MODULE_V1,
    &ngx_stream_ssl_fingerprint_module_ctx,              /* module context */
    ngx_stream_ssl_fingerprint_commands,                 /* module directives */
    NGX_STREAM_MODULE,                                   /* module type */
    NULL,                                                /* init master */
    NULL,                                                /* init module */
    NULL,                                                /* init process */
    NULL,                                                /* init thread */
    NULL,                                                /* exit thread */
    NULL,                                                /* exit process */
    NULL,                                                /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_stream_variable_t  ngx_stream_ssl_fingerprint_vars[] = {

    { ngx_string("ssl_greased"), NULL,
      ngx_stream_ssl_greased,
      0, NGX_STREAM_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_fingerprint_ja3"), NULL,
      ngx_stream_ssl_fingerprint_ja3,
      0, NGX_STREAM_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_fingerprint_ja3_hash"), NULL,
      ngx_stream_ssl_fingerprint_ja3_hash,
      0, NGX_STREAM_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_fingerprint_ja4_r"), NULL,
      ngx_stream_ssl_fingerprint_ja4_r,
      0, NGX_STREAM_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_fingerprint_ja4"), NULL,
      ngx_stream_ssl_fingerprint_ja4,
      0, NGX_STREAM_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_fingerprint_ja4_ro"), NULL,
      ngx_stream_ssl_fingerprint_ja4_ro,
      0, NGX_STREAM_VAR_NOCACHEABLE, 0 },

    { ngx_string("ssl_fingerprint_ja4_o"), NULL,
      ngx_stream_ssl_fingerprint_ja4_o,
      0, NGX_STREAM_VAR_NOCACHEABLE, 0 },

      ngx_stream_null_variable

};


static ngx_int_t
ngx_stream_ssl_fingerprint_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_ssl_fingerprint_vars; v->name.len; v++) {
        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_stream_ssl_fingerprint_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_ssl_fingerprint_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_stream_ssl_fingerprint_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_stream_ssl_fingerprint_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_stream_ssl_fingerprint_main_conf_t  *smcf = conf;

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
ngx_stream_ssl_fingerprint_is_available(ngx_stream_session_t *s)
{
    if (!ngx_ssl_fingerprint_enabled) {
        return NGX_DECLINED;
    }

    if (s->connection == NULL) {
        return NGX_DECLINED;
    }

    if (s->connection->ssl == NULL) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_ssl_greased(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    if (ngx_stream_ssl_fingerprint_is_available(s) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja3(s->connection) == NGX_DECLINED) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    v->len = 1;
    v->data = (u_char *) (s->connection->ssl->fp_greased ? "1" : "0");

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_ssl_fingerprint_ja3(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    if (ngx_stream_ssl_fingerprint_is_available(s) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja3(s->connection) == NGX_DECLINED) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    v->data = s->connection->ssl->fp_ja3_str.data;
    v->len = s->connection->ssl->fp_ja3_str.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_ssl_fingerprint_ja3_hash(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    if (ngx_stream_ssl_fingerprint_is_available(s) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja3_hash(s->connection) == NGX_DECLINED) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    v->data = s->connection->ssl->fp_ja3_hash.data;
    v->len = s->connection->ssl->fp_ja3_hash.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_ssl_fingerprint_ja4_r(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    if (ngx_stream_ssl_fingerprint_is_available(s) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja4_r(s->connection) == NGX_DECLINED) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    v->data = s->connection->ssl->fp_ja4_r.data;
    v->len = s->connection->ssl->fp_ja4_r.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_ssl_fingerprint_ja4(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    if (ngx_stream_ssl_fingerprint_is_available(s) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja4(s->connection) == NGX_DECLINED) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    v->data = s->connection->ssl->fp_ja4.data;
    v->len = s->connection->ssl->fp_ja4.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_ssl_fingerprint_ja4_ro(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    if (ngx_stream_ssl_fingerprint_is_available(s) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja4_ro(s->connection) == NGX_DECLINED) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    v->data = s->connection->ssl->fp_ja4_ro.data;
    v->len = s->connection->ssl->fp_ja4_ro.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_ssl_fingerprint_ja4_o(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    if (ngx_stream_ssl_fingerprint_is_available(s) != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja4_o(s->connection) == NGX_DECLINED) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    v->data = s->connection->ssl->fp_ja4_o.data;
    v->len = s->connection->ssl->fp_ja4_o.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
