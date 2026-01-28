#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_http_v2.h>
#include <ngx_md5.h>
#include <ngx_ssl_fingerprint.h>


#define NGX_SSL_FINGERPRINT_JA4_A_LEN   10
#define NGX_SSL_FINGERPRINT_JA4_B_LEN   12
#define NGX_SSL_FINGERPRINT_JA4_C_LEN   12


#define ngx_ssl_fingerprint_is_grease(code)                                   \
    (((code) & 0x0f0f) == 0x0a0a && ((code) & 0xff) == ((code) >> 8))         \


static inline unsigned char *
ngx_ssl_fingerprint_append_uint16(unsigned char *dst, uint16_t n)
{
    if (n < 10) {
        dst[0] = n + '0';
        dst++;

    } else if (n < 100) {
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 2;

    } else if (n < 1000) {
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 3;

    }  else if (n < 10000) {
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 4;

    } else {
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 5;
    }

    return dst;
}


/**
 * Params:
 *      c and c->ssl should be valid pointers
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja3_str is already set
 *      NGX_ERROR - something went wrong
 */
int ngx_ssl_fingerprint_ja3(ngx_connection_t *c)
{
    u_char       *p, *data;
    size_t        num, i;
    uint16_t      n, greased;

    p = NULL;
    num = 0;
    greased = 0;

    data = c->ssl->fp_ja3_data.data;
    if (data == NULL) {
        /**
         *  NOTE:
         *  If we can't set it in OpenSSL,
         *  then something defenetly something went wrong.
         *  Typical production configuration has log level set to error,
         *  this would help to debug this case, if it happened.
         */
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                "ngx_ssl_fingerprint: ja3 fp_ja_data is null");
        return NGX_ERROR;
    }

    if (c->ssl->fp_ja3_str.data != NULL) {
        return NGX_OK;
    }

    c->ssl->fp_ja3_str.len = c->ssl->fp_ja3_data.len * 3;
    c->ssl->fp_ja3_str.data = ngx_pnalloc(c->pool, c->ssl->fp_ja3_str.len);
    if (c->ssl->fp_ja3_str.data == NULL) {
        /* else we break a data stream */
        c->ssl->fp_ja3_str.len = 0;
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_fingerprint: "
                  "ja3 alloc bytes: %d", c->ssl->fp_ja3_str.len);

    /* version */
    p = c->ssl->fp_ja3_str.data;
    p = ngx_ssl_fingerprint_append_uint16(p, *(uint16_t *) data);
    *p++ = ',';
    data += 2;

    /* ciphers */
    num = *(uint16_t *) data;
    for (i = 2; i <= num; i += 2) {
        n = ((uint16_t) data[i]) << 8 | ((uint16_t) data[i + 1]);

        if (!ngx_ssl_fingerprint_is_grease(n)) {
            p = ngx_ssl_fingerprint_append_uint16(p, n);
            *p++ = '-';

        } else if (greased == 0) {
            greased = n;
        }
    }

    *(p - 1) = ',';
    data += 2 + num;

    /* extensions */
    num = *(uint16_t *) data;
    for (i = 2; i <= num; i += 2) {
        n = *(uint16_t *) (data + i);

        if (!ngx_ssl_fingerprint_is_grease(n)) {
            p = ngx_ssl_fingerprint_append_uint16(p, n);
            *p++ = '-';
        }
    }

    if (num != 0) {
        *(p - 1) = ',';
        data += 2 + num;

    } else {
        *(p++) = ',';
    }

    /* groups */
    num = *(uint16_t *) data;
    for (i = 2; i < num; i += 2) {
        n = ((uint16_t) data[i]) << 8 | ((uint16_t) data[i + 1]);

        if (!ngx_ssl_fingerprint_is_grease(n)) {
            p = ngx_ssl_fingerprint_append_uint16(p, n);
            *p++ = '-';
        }
    }

    if (num != 0) {
        *(p - 1) = ',';
        data += num;

    } else {
        *(p++) = ',';
    }

    /* formats */
    num = *(uint8_t *) data;
    for (i = 1; i < num; i++) {
        p = ngx_ssl_fingerprint_append_uint16(p, (uint16_t) data[i]);
        *p++ = '-';
    }

    if (num != 0) {
        data += num;
        *(p - 1) = ',';
        *p-- = 0;
    }

    /* end */
    c->ssl->fp_ja3_str.len = p - c->ssl->fp_ja3_str.data;

    /* greased */
    c->ssl->fp_tls_greased = greased;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_fingerprint: "
                  "ja3 str=%V, len=%d", &c->ssl->fp_ja3_str,
                  c->ssl->fp_ja3_str.len);

    return NGX_OK;
}


/**
 * Params:
 *      c and c->ssl should be valid pointers and tested before.
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja3_hash is alread set
 *      NGX_ERROR - something went wrong
 */
int ngx_ssl_fingerprint_ja3_hash(ngx_connection_t *c)
{
    ngx_md5_t       ctx;
    u_char          hash_buf[16];

    if (c->ssl->fp_ja3_hash.len > 0) {
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja3(c) != NGX_OK) {
        return NGX_ERROR;
    }

    c->ssl->fp_ja3_hash.len = 32;
    c->ssl->fp_ja3_hash.data = ngx_pnalloc(c->pool, c->ssl->fp_ja3_hash.len);
    if (c->ssl->fp_ja3_hash.data == NULL) {
        /* else we can break a stream */
        c->ssl->fp_ja3_hash.len = 0;
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_fingerprint: "
                  "ja3_hash alloc bytes: %d", c->ssl->fp_ja3_hash.len);

    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, c->ssl->fp_ja3_str.data, c->ssl->fp_ja3_str.len);
    ngx_md5_final(hash_buf, &ctx);
    ngx_hex_dump(c->ssl->fp_ja3_hash.data, hash_buf, 16);

    return NGX_OK;
}


static const u_char *
ngx_ssl_fingerprint_convert_version_to_string(uint16_t tls_version)
{
    switch (tls_version) {
    case 0x304:
        return (u_char *) "13";

    case 0x303:
        return (u_char *) "12";

    case 0x302:
        return (u_char *) "11";

    case 0x301:
        return (u_char *) "10";

    case 0x300:
        return (u_char *) "s3";

    case 0x200:
        return (u_char *) "s2";

    case 0x100:
        return (u_char *) "s1";

    case 0xfeff:
        return (u_char *) "d1";

    case 0xfefd:
        return (u_char *) "d2";

    case 0xfefc:
        return (u_char *) "d3";

    default:
        return (u_char *) "00";
    }
}


static u_char *
ngx_ssl_fingerprint_append_count_as_two_digit_string(u_char *dst,
    uint16_t count)
{
    if (count <= 9) {
        *dst++ = '0';
    }

    return ngx_ssl_fingerprint_append_uint16(dst, ngx_min(count, 99));
}


static int
ngx_ssl_fingerprint_cmp_uint16(const void *p1, const void *p2)
{
    uint16_t u1 = *(const uint16_t *)p1;
    uint16_t u2 = *(const uint16_t *)p2;

    if (u1 > u2)
        return 1;
    if (u1 < u2)
        return -1;
    return 0;
}


static void
ngx_ssl_fingerprint_sort_uint16(uint16_t *data, size_t count)
{
    ngx_qsort(data, count, sizeof(uint16_t), ngx_ssl_fingerprint_cmp_uint16);
}


static uint16_t *
ngx_ssl_fingerprint_ja4_clean_ciphers(ngx_connection_t *c,
    const uint16_t *data, size_t len, size_t *out_num, int original)
{
    const uint16_t  *end, *p;
    uint16_t        *values, *q;
    size_t           n;

    end = (uint16_t *) ((uint8_t *) data + len);
    n = 0;

    for (p = data; p < end; p++) {
        if (!ngx_ssl_fingerprint_is_grease(*p)) {
            n++;
        }
    }

    values = ngx_pnalloc(c->pool, n * sizeof(uint16_t));
    if (values == NULL) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0, "ngx_ssl_fingerprint: ja4_r "
                "out of memory for cleaned ciphers");
        return NULL;
    }

    q = values;
    for (p = data; p < end; p++) {
        if (!ngx_ssl_fingerprint_is_grease(*p))
            *q++ = ntohs(*(uint16_t *) p);
    }

    if (!original) {
        ngx_ssl_fingerprint_sort_uint16(values, n);
    }

    *out_num = n;

    return values;
}


static int
ngx_ssl_fingerprint_is_ignored_non_grease_extension(uint16_t extension)
{
    return extension == TLSEXT_TYPE_server_name
           || extension == TLSEXT_TYPE_application_layer_protocol_negotiation;
}


static int
ngx_ssl_fingerprint_reject_no_extension(uint16_t extension)
{
    return 0;
}


static uint16_t *
ngx_ssl_fingerprint_ja4_clean_extensions(ngx_connection_t *c,
    const uint16_t *data, size_t len, size_t *out_num_exts,
    size_t *out_num_cleaned_exts, int original)
{
    const uint16_t  *end, *p;
    uint16_t        *values, *q;
    size_t           num_exts, num_cleaned_exts;
    int            (*filter) (uint16_t);

    end = (uint16_t *) ((uint8_t *) data + len);
    num_exts = 0;
    num_cleaned_exts = 0;

    if (original) {
        filter = ngx_ssl_fingerprint_reject_no_extension;

    } else {
        filter = ngx_ssl_fingerprint_is_ignored_non_grease_extension;
    }

    for (p = data; p < end; p++) {
        if (!ngx_ssl_fingerprint_is_grease(*p)) {
            num_exts++;
            if (!filter(*p)) {
                num_cleaned_exts++;
            }
        }
    }

    values = ngx_pnalloc(c->pool, num_cleaned_exts * sizeof(uint16_t));
    if (values == NULL) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0, "ngx_ssl_fingerprint: ja4_r "
                "out of memory for cleaned extensions");
        return NULL;
    }

    q = values;
    for (p = data; p < end; p++) {
        if (!ngx_ssl_fingerprint_is_grease(*p) && !filter(*p)) {
            *q++ = *p;
        }
    }

    if (!original) {
        ngx_ssl_fingerprint_sort_uint16(values, num_cleaned_exts);
    }

    *out_num_exts = num_exts;
    *out_num_cleaned_exts = num_cleaned_exts;

    return values;
}


static u_char *
ngx_ssl_fingerprint_append_hex_uint16(u_char *dst, const uint16_t *src,
    size_t count)
{
    const uint16_t *p, *end;
    u_char          hi, lo;

    static u_char   hex[] = "0123456789abcdef";
    end = src + count;

    for (p = src; p < end; p++) {
        if (p > src) {
            *dst++ = ',';
        }

        hi = (uint8_t)(*p >> 8);
        lo = (uint8_t)(*p & 0xff);
        *dst++ = hex[hi >> 4];
        *dst++ = hex[hi & 0xf];
        *dst++ = hex[lo >> 4];
        *dst++ = hex[lo & 0xf];
    }

    return dst;
}


static u_char *
ngx_ssl_fingerprint_append_hex_uint16_from_bytes(u_char *dst,
    const u_char *src, size_t src_byte_len)
{
    const u_char  *p, *end;
    u_char         hi, lo;
    static u_char  hex[] = "0123456789abcdef";

    p = src;
    end = src + src_byte_len;

    while (p < end) {
        if (p > src) {
            *dst++ = ',';
        }

        hi = *p++;
        lo = *p++;
        *dst++ = hex[hi >> 4];
        *dst++ = hex[hi & 0xf];
        *dst++ = hex[lo >> 4];
        *dst++ = hex[lo & 0xf];
    }

    return dst;
}


static int
ngx_ssl_fingerprint_ja4_r_helper(ngx_connection_t *c, ngx_str_t *dst_field,
    int original)
{
    const u_char    *data, *first_alpn, *sig_algos;
    u_char          *p, sni;
    uint16_t        *ciphers_data, *exts_data;
    uint16_t         tls_version, ciphers_len, exts_len, sig_algos_len;
	uint16_t         sig_algos_data_len;
    size_t           num_ciphers, num_exts, num_cleaned_exts, num_sig_algos;

    first_alpn = NULL;
    sig_algos = NULL;
    p = NULL;
    num_sig_algos = 0;

    data = c->ssl->fp_ja4_data.data;
    if (data == NULL) {
        /**
         *  NOTE:
         *  If we can't set it in OpenSSL,
         *  then something defenetly something went wrong.
         *  Typical production configuration has log level set to error,
         *  this would help to debug this case, if it happened.
         */
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                "ngx_ssl_fingerprint: fp_ja4_data is null");
        return NGX_ERROR;
    }

    if (dst_field->data != NULL) {
        return NGX_OK;
    }

    data = c->ssl->fp_ja4_data.data
           + sizeof(char)      /* protocol */
           + sizeof(char)      /* sni */
           + sizeof(uint16_t)  /* version */
           + sizeof(char) * 2; /* first ALPN */

    (void) ngx_copy(&ciphers_len, data, sizeof(uint16_t));
    data += sizeof(uint16_t);

    ciphers_data = ngx_ssl_fingerprint_ja4_clean_ciphers(c,
                                          (const uint16_t *) data, ciphers_len,
                                          &num_ciphers, original);

    if (ciphers_data == NULL) {
        dst_field->len = 0;
        return NGX_ERROR;
    }

    data += ciphers_len;

    (void) ngx_copy(&exts_len, data, sizeof(uint16_t));
    data += sizeof(uint16_t);
    exts_data = ngx_ssl_fingerprint_ja4_clean_extensions(c,
                                  (const uint16_t *) data, exts_len, &num_exts,
                                  &num_cleaned_exts, original);

    if (exts_data == NULL) {
        dst_field->len = 0;
        return NGX_ERROR;
    }

    data += exts_len;

    (void) ngx_copy(&sig_algos_len, data, sizeof(uint16_t));
    data += sizeof(uint16_t);

    if (sig_algos_len >= sizeof(uint16_t)) {
        sig_algos_data_len = (*data << 8) | *(data + 1); /* big endian */
        if (sig_algos_len != sig_algos_data_len + sizeof(uint16_t)) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "ngx_ssl_fingerprint: ja4_r_helper "
                          "sig_algos_len mismatch, outer_len=%d, "
			              "inner_len=%d, diff must be 2",
                          sig_algos_len, sig_algos_data_len);
            dst_field->len = 0;
            return NGX_ERROR;
        }
    
        if (sig_algos_data_len > 0) {
            num_sig_algos = sig_algos_data_len / sizeof(uint16_t);
            sig_algos = data + sizeof(uint16_t);
            data = sig_algos + sig_algos_data_len;
        }
    }

    if (data != c->ssl->fp_ja4_data.data + c->ssl->fp_ja4_data.len) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "ngx_ssl_fingerprint: ja4_r_helper "
                      "end mismatch, got=%p, want=%p, original=%d",
                      data, c->ssl->fp_ja4_data.data + c->ssl->fp_ja4_data.len,
		              original);
    }

    dst_field->len =1 /* protocol */
          + 2 /* TLS version */
          + 1 /* SNI */
          + 2 /* Number of Cipher Suites */
          + 2 /* Number of Extensions */
          + 2 /* First ALPN */
          + 1 /* '_' */
          + 4 * num_ciphers + (num_ciphers - 1) /* ciphers 4-char hex csv */
          + 1                                             /* '_' */
          + 4 * num_cleaned_exts + (num_cleaned_exts - 1) /* hex csv */
          + (num_sig_algos > 0
             ? 1 + 4 * num_sig_algos + (num_sig_algos - 1) /* '_' hex csv */
             : 0);
    dst_field->data = ngx_pnalloc(c->pool, dst_field->len);
    if (dst_field->data == NULL) {
        /* else we break a data stream */
        dst_field->len = 0;
        return NGX_ERROR;
    }

    /*
     * https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
     */

    data = c->ssl->fp_ja4_data.data;

    /* protocol */
    p = dst_field->data;
    *p++ = *data++;
    sni = *data++;

    /* version */
    tls_version = *(uint16_t *) data;
    data += sizeof(uint16_t);
    p = ngx_copy(p,
                ngx_ssl_fingerprint_convert_version_to_string(tls_version), 2);

    first_alpn = data;
    data += 2;

    /* sni */
    *p++ = sni;

    /* number of ciphers */
    p = ngx_ssl_fingerprint_append_count_as_two_digit_string(p, num_ciphers);

    /* number of extensions */
    p = ngx_ssl_fingerprint_append_count_as_two_digit_string(p, num_exts);

    /* first ALPN */
    p = ngx_copy(p, first_alpn, 2);

    /* ciphers */
    *p++ = '_';
    p = ngx_ssl_fingerprint_append_hex_uint16(p, ciphers_data, num_ciphers);

    /* extensions */
    *p++ = '_';
    p = ngx_ssl_fingerprint_append_hex_uint16(p, exts_data, num_cleaned_exts);

    /* signature algorithms */
    if (num_sig_algos > 0) {
        *p++ = '_';
        p = ngx_ssl_fingerprint_append_hex_uint16_from_bytes(p, sig_algos,
                                                           sig_algos_data_len);
    }

    return NGX_OK;
}


static int
ngx_ssl_fingerprint_ja4_helper(ngx_connection_t *c, ngx_str_t *raw_field,
	ngx_str_t *dst_field, int original)
{
    u_char          hash_buf[EVP_MAX_MD_SIZE], *ptr, *src, *part_end;
    unsigned int    hash_len;
    const EVP_MD   *digest;
    EVP_MD_CTX     *ctx;
    int             ret;

    ret = NGX_ERROR;

    if (dst_field->len > 0) {
        return NGX_OK;
    }

    if (ngx_ssl_fingerprint_ja4_r_helper(c, raw_field, original) != NGX_OK) {
        return NGX_ERROR;
    }

    dst_field->len = NGX_SSL_FINGERPRINT_JA4_A_LEN + 1
                     + NGX_SSL_FINGERPRINT_JA4_B_LEN + 1
                     + NGX_SSL_FINGERPRINT_JA4_C_LEN;
    dst_field->data = ngx_pnalloc(c->pool, dst_field->len);
    if (dst_field->data == NULL) {
        /* else we can break a stream */
        dst_field->len = 0;
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0,
                  "ngx_ssl_fingerprint: ja4_hash alloc bytes: %d",
                  dst_field->len);

    /* JA4_a part */
    src = raw_field->data;
    ptr = dst_field->data;
    ptr = ngx_cpymem(ptr, src, NGX_SSL_FINGERPRINT_JA4_A_LEN);
    *ptr++ = '_';

    ctx = EVP_MD_CTX_new();
    digest = EVP_sha256();

    /* JA4_b part */
    src += NGX_SSL_FINGERPRINT_JA4_A_LEN + 1;
    part_end = (u_char *) ngx_strchr(src, '_');

    EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT);

    if ((EVP_DigestInit_ex(ctx, digest, NULL)
         && EVP_DigestUpdate(ctx, src, part_end - src)
         && EVP_DigestFinal_ex(ctx, hash_buf, &hash_len)) != 1)
    {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "ngx_ssl_fingerprint: ja4_helper "
                      "failed to digest JA4_b");
        goto failed;
    }

    ngx_hex_dump(ptr, hash_buf, NGX_SSL_FINGERPRINT_JA4_B_LEN / 2);
    ptr += NGX_SSL_FINGERPRINT_JA4_B_LEN;
    *ptr++ = '_';

    /* JA4_c part */
    src = part_end + 1;
    part_end = raw_field->data + raw_field->len;

    if (part_end == src) {
        (void) ngx_copy(ptr, "000000000000", NGX_SSL_FINGERPRINT_JA4_C_LEN);

    } else {
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT);

        if ((EVP_DigestInit_ex(ctx, digest, NULL)
             && EVP_DigestUpdate(ctx, src, part_end - src)
             && EVP_DigestFinal_ex(ctx, hash_buf, &hash_len)) != 1)
        {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "ngx_ssl_fingerprint: ja4_helper "
                          "failed to digest JA4_c");
            goto failed;
        }

        ngx_hex_dump(ptr, hash_buf, NGX_SSL_FINGERPRINT_JA4_C_LEN / 2);
    }

    ret = NGX_OK;

failed:

    EVP_MD_CTX_free(ctx);

    return ret;
}


/**
 * Params:
 *      c and c->ssl should be valid pointers
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja4_r is already set
 *      NGX_ERROR - something went wrong
 */
int
ngx_ssl_fingerprint_ja4_r(ngx_connection_t *c)
{
    return ngx_ssl_fingerprint_ja4_r_helper(c, &c->ssl->fp_ja4_r, 0);
}


/**
 * Params:
 *      c and c->ssl should be valid pointers and tested before.
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja4 is alread set
 *      NGX_ERROR - something went wrong
 */
int
ngx_ssl_fingerprint_ja4(ngx_connection_t *c)
{
    return ngx_ssl_fingerprint_ja4_helper(c, &c->ssl->fp_ja4_r,
                                          &c->ssl->fp_ja4, 0);
}


/**
 * Params:
 *      c and c->ssl should be valid pointers
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja4_ro is already set
 *      NGX_ERROR - something went wrong
 */
int
ngx_ssl_fingerprint_ja4_ro(ngx_connection_t *c)
{
    return ngx_ssl_fingerprint_ja4_r_helper(c, &c->ssl->fp_ja4_ro, 1);
}


/**
 * Params:
 *      c and c->ssl should be valid pointers and tested before.
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja4_o is alread set
 *      NGX_ERROR - something went wrong
 */
int
ngx_ssl_fingerprint_ja4_o(ngx_connection_t *c)
{
    return ngx_ssl_fingerprint_ja4_helper(c, &c->ssl->fp_ja4_ro,
                                          &c->ssl->fp_ja4_o, 1);
}
