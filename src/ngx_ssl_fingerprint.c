/*
 * Copyright (C) 2020-2024 Phus Lu
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_md5.h>
#include <ngx_ssl_fingerprint.h>


#define ngx_ssl_fingerprint_grease(n)                                         \
    (((n) & 0x0f0f) == 0x0a0a && ((n) >> 8) == ((n) & 0xff))

#define ngx_ssl_fingerprint_alnum(c)                                          \
    (((c) >= '0' && (c) <= '9') || ((c) >= 'A' && (c) <= 'Z')                 \
     || ((c) >= 'a' && (c) <= 'z'))


enum {
    NGX_SSL_FP_CIPHERS,
    NGX_SSL_FP_EXTENSIONS,
    NGX_SSL_FP_GROUPS,
    NGX_SSL_FP_FORMATS,
    NGX_SSL_FP_SIGALGS,
    NGX_SSL_FP_FIELDS
};


typedef struct {
    ngx_str_t   fields[NGX_SSL_FP_FIELDS];
    ngx_str_t   values[NGX_SSL_FP_VARIABLES];
    uint16_t    legacy_version;
    uint16_t    version;
    u_char      transport;
    u_char      sni;
    u_char      alpn[2];
    ngx_flag_t  greased;
} ngx_ssl_fingerprint_t;


ngx_uint_t    ngx_ssl_fingerprint_enabled;
ngx_cycle_t  *ngx_ssl_fingerprint_cycle;

static u_char  ngx_ssl_fingerprint_hex[] = "0123456789abcdef";


static uint16_t
ngx_ssl_fingerprint_uint16(const u_char *p)
{
    return (uint16_t) ((p[0] << 8) | p[1]);
}


static ngx_int_t
ngx_ssl_fingerprint_vector(const u_char **pos, const u_char *end,
    size_t width, ngx_str_t *value)
{
    size_t         len;
    const u_char  *p;

    p = *pos;
    if ((size_t) (end - p) < width) {
        return NGX_ERROR;
    }

    len = width == 1 ? p[0] : ngx_ssl_fingerprint_uint16(p);
    p += width;
    if ((size_t) (end - p) < len) {
        return NGX_ERROR;
    }

    value->data = (u_char *) p;
    value->len = len;
    *pos = p + len;

    return NGX_OK;
}


/* All pointers returned here refer to the message callback's input. */
static ngx_int_t
ngx_ssl_fingerprint_parse(const u_char *data, size_t len,
    ngx_ssl_fingerprint_t *fp, ngx_str_t *extensions)
{
    u_char         first, final;
    size_t         i, width;
    uint16_t       type, version;
    ngx_str_t      value, list, protocol;
    ngx_uint_t     seen, bit, field;
    const u_char  *p, *end, *last, *q;

    if (len < 4 + 2 + 32 || data[0] != SSL3_MT_CLIENT_HELLO
        || ((size_t) data[1] << 16 | (size_t) data[2] << 8 | data[3])
            != len - 4)
    {
        return NGX_ERROR;
    }

    p = data + 4;
    end = data + len;
    fp->legacy_version = ngx_ssl_fingerprint_uint16(p);
    fp->version = fp->legacy_version;
    fp->sni = 'i';
    fp->alpn[0] = '0';
    fp->alpn[1] = '0';
    p += 2 + 32;

    if (ngx_ssl_fingerprint_vector(&p, end, 1, &value) != NGX_OK
        || value.len > 32
        || ngx_ssl_fingerprint_vector(&p, end, 2,
                                      &fp->fields[NGX_SSL_FP_CIPHERS]) != NGX_OK
        || (fp->fields[NGX_SSL_FP_CIPHERS].len & 1)
        || ngx_ssl_fingerprint_vector(&p, end, 1, &value) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (p == end) {
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_vector(&p, end, 2, extensions) != NGX_OK
        || p != end)
    {
        return NGX_ERROR;
    }

    p = extensions->data;
    seen = 0;

    while (p < end) {
        if ((size_t) (end - p) < 4) {
            return NGX_ERROR;
        }

        type = ngx_ssl_fingerprint_uint16(p);
        p += 2;

        if (ngx_ssl_fingerprint_vector(&p, end, 2, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        fp->fields[NGX_SSL_FP_EXTENSIONS].len += 2;
        q = value.data;
        last = q + value.len;
        bit = 0;

        switch (type) {

        case 0:                         /* server_name */
            bit = 1;
            fp->sni = 'd';
            break;

        case 10:                        /* supported_groups */
        case 11:                        /* ec_point_formats */
        case 13:                        /* signature_algorithms */
            field = type == 10 ? NGX_SSL_FP_GROUPS
                    : type == 11 ? NGX_SSL_FP_FORMATS : NGX_SSL_FP_SIGALGS;
            bit = (ngx_uint_t) 1 << field;
            width = type == 11 ? 1 : 2;

            if (ngx_ssl_fingerprint_vector(&q, last, width, &list) != NGX_OK
                || q != last || (width == 2 && (list.len & 1)))
            {
                return NGX_ERROR;
            }

            fp->fields[field] = list;
            break;

        case 16:                        /* ALPN */
            bit = 1 << 5;

            if (ngx_ssl_fingerprint_vector(&q, last, 2, &list) != NGX_OK
                || q != last)
            {
                return NGX_ERROR;
            }

            q = list.data;
            i = 0;

            while (q < last) {
                if (ngx_ssl_fingerprint_vector(&q, last, 1, &protocol)
                    != NGX_OK
                    || protocol.len == 0)
                {
                    return NGX_ERROR;
                }

                if (i++ != 0) {
                    continue;
                }

                first = protocol.data[0];
                final = protocol.data[protocol.len - 1];

                if (ngx_ssl_fingerprint_alnum(first)
                    && ngx_ssl_fingerprint_alnum(final))
                {
                    fp->alpn[0] = first;
                    fp->alpn[1] = final;

                } else {
                    fp->alpn[0] = ngx_ssl_fingerprint_hex[first >> 4];
                    fp->alpn[1] = ngx_ssl_fingerprint_hex[final & 0x0f];
                }
            }

            break;

        case 43:                        /* supported_versions */
            bit = 1 << 6;

            if (ngx_ssl_fingerprint_vector(&q, last, 1, &list) != NGX_OK
                || q != last || (list.len & 1))
            {
                return NGX_ERROR;
            }

            fp->version = 0;

            for (i = 0; i < list.len; i += 2) {
                version = ngx_ssl_fingerprint_uint16(list.data + i);

                if (!ngx_ssl_fingerprint_grease(version)
                    && version > fp->version)
                {
                    fp->version = version;
                }
            }

            break;
        }

        if (seen & bit) {
            return NGX_ERROR;
        }

        seen |= bit;
    }

    return NGX_OK;
}


void
ngx_ssl_fingerprint_message(int write_p, int version, int content_type,
    const void *buf, size_t len, ngx_ssl_conn_t *ssl, void *arg)
{
    u_char                 *p;
    size_t                  i, size, offset;
    ngx_str_t               extensions;
    const u_char           *data;
    ngx_connection_t       *c;
    ngx_ssl_fingerprint_t   hello, *fp;

    data = buf;
    if (!ngx_ssl_fingerprint_enabled || write_p
        || content_type != SSL3_RT_HANDSHAKE || len < 4
        || data[0] != SSL3_MT_CLIENT_HELLO)
    {
        return;
    }

    c = ngx_ssl_get_connection(ssl);
    if (c == NULL || c->ssl == NULL || c->ssl->fp_collected) {
        return;
    }

    /* HRR and callback retries must not replace the first ClientHello. */

    c->ssl->fp_collected = 1;
    ngx_memzero(&hello, sizeof(hello));
    ngx_str_null(&extensions);

    if (ngx_ssl_fingerprint_parse(data, len, &hello, &extensions) != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "ssl fingerprint: invalid ClientHello");
        return;
    }

    hello.transport = 't';

#if (NGX_QUIC)
    if (c->quic || c->type == SOCK_DGRAM) {
        hello.transport = 'q';
    }
#endif

    /* Only retain fingerprint fields, never key shares or extension bodies. */

    size = sizeof(ngx_ssl_fingerprint_t);

    for (i = 0; i < NGX_SSL_FP_FIELDS; i++) {
        size += hello.fields[i].len;
    }

    fp = ngx_palloc(c->pool, size);
    if (fp == NULL) {
        return;
    }

    *fp = hello;
    p = (u_char *) (fp + 1);

    for (i = 0; i < NGX_SSL_FP_FIELDS; i++) {
        fp->fields[i].data = p;

        if (i == NGX_SSL_FP_EXTENSIONS) {
            for (offset = 0; offset < extensions.len; /* void */) {
                data = extensions.data + offset;
                *p++ = data[0];
                *p++ = data[1];
                offset += 4 + ngx_ssl_fingerprint_uint16(data + 2);
            }

        } else if (hello.fields[i].len) {
            p = ngx_cpymem(p, hello.fields[i].data, hello.fields[i].len);
        }
    }

    data = fp->fields[NGX_SSL_FP_CIPHERS].data;
    for (i = 0; i < fp->fields[NGX_SSL_FP_CIPHERS].len; i += 2) {
        if (ngx_ssl_fingerprint_grease(ngx_ssl_fingerprint_uint16(data + i))) {
            fp->greased = 1;
            break;
        }
    }

    c->ssl->fp_ctx = fp;
}


static size_t
ngx_ssl_fingerprint_count(ngx_str_t *field, ngx_uint_t omit_sni_alpn)
{
    size_t    i, n;
    uint16_t  value;

    n = 0;
    for (i = 0; i < field->len; i += 2) {
        value = ngx_ssl_fingerprint_uint16(field->data + i);
        if (!ngx_ssl_fingerprint_grease(value)
            && !(omit_sni_alpn && (value == 0 || value == 16)))
        {
            n++;
        }
    }

    return n;
}


static u_char *
ngx_ssl_fingerprint_decimal(u_char *p, ngx_uint_t value)
{
    u_char  *last;
    u_char   digits[5];

    last = digits + sizeof(digits);

    do {
        *--last = (u_char) ('0' + value % 10);
        value /= 10;
    } while (value);

    return ngx_cpymem(p, last, digits + sizeof(digits) - last);
}


static ngx_int_t
ngx_ssl_fingerprint_store(ngx_connection_t *c, ngx_str_t *value,
    const u_char *data, size_t len)
{
    u_char  *p;

    p = ngx_pnalloc(c->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, data, len);
    value->data = p;
    value->len = len;

    return NGX_OK;
}


static ngx_int_t
ngx_ssl_fingerprint_ja3(ngx_connection_t *c, ngx_ssl_fingerprint_t *fp,
    ngx_uint_t index)
{
    u_char     *buf, *p;
    size_t      i, j, size, width;
    uint16_t    value;
    ngx_int_t   rc;
    ngx_str_t  *field;
    ngx_md5_t   md5;
    ngx_uint_t  first;
    u_char      small[2048], digest[16], hex[32];

    size = 5 + 4;
    for (i = NGX_SSL_FP_CIPHERS; i <= NGX_SSL_FP_FORMATS; i++) {
        field = &fp->fields[i];
        size += i == NGX_SSL_FP_FORMATS ? field->len * 4 : field->len * 3;
    }

    buf = small;
    if (size > sizeof(small)) {
        buf = ngx_alloc(size, c->log);
        if (buf == NULL) {
            return NGX_ERROR;
        }
    }

    p = ngx_ssl_fingerprint_decimal(buf, fp->legacy_version);
    for (i = NGX_SSL_FP_CIPHERS; i <= NGX_SSL_FP_FORMATS; i++) {
        *p++ = ',';
        first = 1;
        field = &fp->fields[i];
        width = i == NGX_SSL_FP_FORMATS ? 1 : 2;

        for (j = 0; j < field->len; j += width) {
            value = width == 1 ? field->data[j]
                    : ngx_ssl_fingerprint_uint16(field->data + j);
            if (width == 2 && ngx_ssl_fingerprint_grease(value)) {
                continue;
            }

            if (!first) {
                *p++ = '-';
            }

            first = 0;
            p = ngx_ssl_fingerprint_decimal(p, value);
        }
    }

    if (index == NGX_SSL_FP_JA3_HASH) {
        ngx_md5_init(&md5);
        ngx_md5_update(&md5, buf, p - buf);
        ngx_md5_final(digest, &md5);
        ngx_hex_dump(hex, digest, sizeof(digest));
        rc = ngx_ssl_fingerprint_store(c, &fp->values[index], hex, sizeof(hex));

    } else {
        rc = ngx_ssl_fingerprint_store(c, &fp->values[index], buf, p - buf);
    }

    if (buf != small) {
        ngx_free(buf);
    }

    return rc;
}


static int
ngx_ssl_fingerprint_compare(const void *a, const void *b)
{
    uint16_t  x, y;

    x = *(const uint16_t *) a;
    y = *(const uint16_t *) b;

    return (x > y) - (x < y);
}


static u_char *
ngx_ssl_fingerprint_csv(u_char *p, ngx_str_t *field, uint16_t *values,
    ngx_uint_t sort, ngx_uint_t omit_sni_alpn)
{
    size_t    i, n;
    uint16_t  value;

    n = 0;
    for (i = 0; i < field->len; i += 2) {
        value = ngx_ssl_fingerprint_uint16(field->data + i);
        if (!ngx_ssl_fingerprint_grease(value)
            && !(omit_sni_alpn && (value == 0 || value == 16)))
        {
            values[n++] = value;
        }
    }

    if (sort && n > 1) {
        ngx_qsort(values, n, sizeof(uint16_t), ngx_ssl_fingerprint_compare);
    }

    for (i = 0; i < n; i++) {
        if (i) {
            *p++ = ',';
        }

        value = values[i];
        *p++ = ngx_ssl_fingerprint_hex[value >> 12];
        *p++ = ngx_ssl_fingerprint_hex[(value >> 8) & 15];
        *p++ = ngx_ssl_fingerprint_hex[(value >> 4) & 15];
        *p++ = ngx_ssl_fingerprint_hex[value & 15];
    }

    return p;
}


static const char *
ngx_ssl_fingerprint_version(uint16_t version)
{
    switch (version) {

    case 0x0002:
        return "s2";

    case 0x0300:
        return "s3";

    case 0x0301:
        return "10";

    case 0x0302:
        return "11";

    case 0x0303:
        return "12";

    case 0x0304:
        return "13";

    default:
        return "00";
    }
}


static ngx_int_t
ngx_ssl_fingerprint_digest(EVP_MD_CTX *ctx, u_char *out, u_char *data,
    size_t len)
{
    unsigned int  size;
    u_char        digest[EVP_MAX_MD_SIZE];

    if (len == 0) {
        ngx_memset(out, '0', 12);
        return NGX_OK;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1
        || EVP_DigestUpdate(ctx, data, len) != 1
        || EVP_DigestFinal_ex(ctx, digest, &size) != 1 || size != 32)
    {
        return NGX_ERROR;
    }

    ngx_hex_dump(out, digest, 6);

    return NGX_OK;
}


static ngx_int_t
ngx_ssl_fingerprint_ja4(ngx_connection_t *c, ngx_ssl_fingerprint_t *fp,
    ngx_uint_t index)
{
    u_char      *buf, *p, *ciphers, *exts;
    size_t       nciphers, nexts, nsigalgs, total_exts, size, count;
    size_t       cipher_len, ext_len;
    uint16_t    *values;
    ngx_int_t    rc;
    ngx_uint_t   original;
    EVP_MD_CTX  *ctx;
    u_char       small[2048], hash[36];
    uint16_t     small_values[128];

    original = index == NGX_SSL_FP_JA4_RO || index == NGX_SSL_FP_JA4_O;
    nciphers = ngx_ssl_fingerprint_count(&fp->fields[NGX_SSL_FP_CIPHERS], 0);
    nexts = ngx_ssl_fingerprint_count(&fp->fields[NGX_SSL_FP_EXTENSIONS],
                                      !original);
    total_exts = ngx_ssl_fingerprint_count(&fp->fields[NGX_SSL_FP_EXTENSIONS],
                                           0);
    nsigalgs = ngx_ssl_fingerprint_count(&fp->fields[NGX_SSL_FP_SIGALGS], 0);

    size = 12 + (nciphers ? 5 * nciphers - 1 : 0)
              + (nexts ? 5 * nexts - 1 : 0)
              + (nsigalgs ? 5 * nsigalgs : 0);
    count = ngx_max(nciphers, ngx_max(nexts, nsigalgs));
    buf = small;
    values = small_values;
    rc = NGX_ERROR;
    ctx = NULL;

    if (size > sizeof(small)) {
        buf = ngx_alloc(size, c->log);
        if (buf == NULL) {
            return NGX_ERROR;
        }
    }

    if (count > sizeof(small_values) / sizeof(uint16_t)) {
        values = ngx_alloc(count * sizeof(uint16_t), c->log);
        if (values == NULL) {
            goto done;
        }
    }

    p = buf;
    *p++ = fp->transport;
    p = ngx_cpymem(p, ngx_ssl_fingerprint_version(fp->version), 2);
    *p++ = fp->sni;
    *p++ = (u_char) ('0' + ngx_min(nciphers, 99) / 10);
    *p++ = (u_char) ('0' + ngx_min(nciphers, 99) % 10);
    *p++ = (u_char) ('0' + ngx_min(total_exts, 99) / 10);
    *p++ = (u_char) ('0' + ngx_min(total_exts, 99) % 10);
    *p++ = fp->alpn[0];
    *p++ = fp->alpn[1];
    *p++ = '_';
    ciphers = p;
    p = ngx_ssl_fingerprint_csv(p, &fp->fields[NGX_SSL_FP_CIPHERS], values,
                                !original, 0);
    cipher_len = p - ciphers;
    *p++ = '_';
    exts = p;
    p = ngx_ssl_fingerprint_csv(p, &fp->fields[NGX_SSL_FP_EXTENSIONS], values,
                                !original, !original);

    if (nsigalgs) {
        *p++ = '_';
        p = ngx_ssl_fingerprint_csv(p, &fp->fields[NGX_SSL_FP_SIGALGS], values,
                                    0, 0);
    }

    ext_len = p - exts;

    if (index == NGX_SSL_FP_JA4_R || index == NGX_SSL_FP_JA4_RO) {
        rc = ngx_ssl_fingerprint_store(c, &fp->values[index], buf, p - buf);
        goto done;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        goto done;
    }

    ngx_memcpy(hash, buf, 11);
    hash[23] = '_';

    if (ngx_ssl_fingerprint_digest(ctx, hash + 11, ciphers, cipher_len)
        != NGX_OK
        || ngx_ssl_fingerprint_digest(ctx, hash + 24, exts, ext_len) != NGX_OK)
    {
        goto done;
    }

    rc = ngx_ssl_fingerprint_store(c, &fp->values[index], hash, sizeof(hash));

done:

    EVP_MD_CTX_free(ctx);

    if (values != small_values && values != NULL) {
        ngx_free(values);
    }

    if (buf != small) {
        ngx_free(buf);
    }

    return rc;
}


ngx_int_t
ngx_ssl_fingerprint_variable(ngx_connection_t *c, ngx_uint_t index,
    ngx_str_t *value)
{
    ngx_int_t               rc;
    ngx_ssl_fingerprint_t  *fp;

    ngx_str_null(value);
    if (!ngx_ssl_fingerprint_enabled || index >= NGX_SSL_FP_VARIABLES
        || c == NULL || c->ssl == NULL || c->ssl->connection == NULL)
    {
        return NGX_DECLINED;
    }

    /* HTTP/3 streams share SSL but have shorter-lived connection pools. */

    c = ngx_ssl_get_connection(c->ssl->connection);
    if (c == NULL || c->ssl == NULL || c->ssl->fp_ctx == NULL) {
        return NGX_DECLINED;
    }

    fp = c->ssl->fp_ctx;
    if (index == NGX_SSL_FP_GREASED) {
        value->data = (u_char *) (fp->greased ? "1" : "0");
        value->len = 1;

        return NGX_OK;
    }

    if (fp->values[index].data == NULL) {
        if (index == NGX_SSL_FP_JA3 || index == NGX_SSL_FP_JA3_HASH) {
            rc = ngx_ssl_fingerprint_ja3(c, fp, index);

        } else {
            rc = ngx_ssl_fingerprint_ja4(c, fp, index);
        }

        if (rc != NGX_OK) {
            return rc;
        }
    }

    *value = fp->values[index];

    return NGX_OK;
}
