#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_http_v2.h>
#include <ngx_md5.h>

#include <nginx_ssl_fingerprint.h>

#define IS_GREASE_CODE(code) (((code)&0x0f0f) == 0x0a0a && ((code)&0xff) == ((code)>>8))

#define JA4_a_len 10
#define JA4_b_len 12
#define JA4_c_len 12

static inline
unsigned char *append_uint8(unsigned char* dst, uint8_t n)
{
    if (n < 10) {
        dst[0] = n + '0';
        dst++;
    } else if (n < 100) {
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 2;
    } else {
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 3;
    }

    return dst;
}

static inline
unsigned char *append_uint16(unsigned char* dst, uint16_t n)
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

static inline
unsigned char *append_uint32(unsigned char* dst, uint32_t n)
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
    } else if (n < 10000) {
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 4;
    } else if (n < 100000) {
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 5;
    } else if (n < 1000000) {
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 6;
    } else if (n < 10000000) {
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 7;
    } else if (n < 100000000) {
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 8;
    } else if (n < 1000000000) {
        dst[8] = n % 10 + '0';
        n /= 10;
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 9;
    } else {
        dst[9] = n % 10 + '0';
        n /= 10;
        dst[8] = n % 10 + '0';
        n /= 10;
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 10;
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
int ngx_ssl_ja3(ngx_connection_t *c)
{
    u_char *ptr = NULL, *data = NULL;
    size_t num = 0, i;
    uint16_t n, greased = 0;

    data = c->ssl->fp_ja3_data.data;
    if (data == NULL) {
        /**
         *  NOTE:
         *  If we can't set it in OpenSSL,
         *  then something defenetly something went wrong.
         *  Typical production configuration has log level set to error,
         *  this would help to debug this case, if it happened.
         */
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja3: fp_ja_data == NULL");
        return NGX_ERROR;
    }

    if (c->ssl->fp_ja3_str.data != NULL) {
        return NGX_OK;
    }

    c->ssl->fp_ja3_str.len = c->ssl->fp_ja3_data.len * 3;
    c->ssl->fp_ja3_str.data = ngx_pnalloc(c->pool, c->ssl->fp_ja3_str.len);
    if (c->ssl->fp_ja3_str.data == NULL) {
        /** Else we break a data stream */
        c->ssl->fp_ja3_str.len = 0;
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_ja3: alloc bytes: [%d]\n", c->ssl->fp_ja3_str.len);

    /* version */
    ptr = c->ssl->fp_ja3_str.data;
    ptr = append_uint16(ptr, *(uint16_t*)data);
    *ptr++ = ',';
    data += 2;

    /* ciphers */
    num = *(uint16_t*)data;
    for (i = 2; i <= num; i += 2) {
        n = ((uint16_t)data[i]) << 8 | ((uint16_t)data[i+1]);
        if (!IS_GREASE_CODE(n)) {
            /* if (data[i] == 0x13) {
                c->ssl->fp_ja3_str.data[2] = '2'; // fixup tls1.3 version
            } */
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
        } else if (greased == 0) {
            greased = n;
        }
    }
    *(ptr-1) = ',';
    data += 2 + num;

    /* extensions */
    num = *(uint16_t*)data;
    for (i = 2; i <= num; i += 2) {
        n = *(uint16_t*)(data+i);
        if (!IS_GREASE_CODE(n)) {
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
        }
    }
    if (num != 0) {
        *(ptr-1) = ',';
        data += 2 + num;
    } else {
        *(ptr++) = ',';
    }

    /* groups */
    num = *(uint16_t*)data;
    for (i = 2; i < num; i += 2) {
        n = ((uint16_t)data[i]) << 8 | ((uint16_t)data[i+1]);
        if (!IS_GREASE_CODE(n)) {
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
        }
    }
    if (num != 0) {
        *(ptr-1) = ',';
        data += num;
    } else {
        *(ptr++) = ',';
    }

    /* formats */
    num = *(uint8_t*)data;
    for (i = 1; i < num; i++) {
        ptr = append_uint16(ptr, (uint16_t)data[i]);
        *ptr++ = '-';
    }
    if (num != 0) {
        data += num;
        *(ptr-1) = ',';
        *ptr-- = 0;
    }

    /* end */
    c->ssl->fp_ja3_str.len = ptr - c->ssl->fp_ja3_str.data;

    /* greased */
    c->ssl->fp_tls_greased = greased;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_ja3: ja3 str=[%V], len=[%d]", &c->ssl->fp_ja3_str, c->ssl->fp_ja3_str.len);

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
int ngx_ssl_ja3_hash(ngx_connection_t *c)
{
    ngx_md5_t ctx;
    u_char hash_buf[16];

    if (c->ssl->fp_ja3_hash.len > 0) {
        return NGX_OK;
    }

    if (ngx_ssl_ja3(c) != NGX_OK) {
        return NGX_ERROR;
    }

    c->ssl->fp_ja3_hash.len = 32;
    c->ssl->fp_ja3_hash.data = ngx_pnalloc(c->pool, c->ssl->fp_ja3_hash.len);
    if (c->ssl->fp_ja3_hash.data == NULL) {
        /** Else we can break a stream */
        c->ssl->fp_ja3_hash.len = 0;
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_ja3_hash: alloc bytes: [%d]\n", c->ssl->fp_ja3_hash.len);

    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, c->ssl->fp_ja3_str.data, c->ssl->fp_ja3_str.len);
    ngx_md5_final(hash_buf, &ctx);
    ngx_hex_dump(c->ssl->fp_ja3_hash.data, hash_buf, 16);

    return NGX_OK;
}

/**
 * Params:
 *      c and h2c should be a valid pointers
 *
 * Returns:
 *      NGX_OK -- h2c->fp_str is set
 *      NGX_ERROR -- something went wrong
 */
int ngx_http2_fingerprint(ngx_connection_t *c, ngx_http_v2_connection_t *h2c)
{
    unsigned char *pstr = NULL;
    unsigned short n = 0;
    size_t i;

    if (h2c->fp_str.len > 0) {
        return NGX_OK;
    }

    n = 4 + h2c->fp_settings.len * 3
        + 10 + h2c->fp_priorities.len * 2
        + h2c->fp_pseudoheaders.len * 2;

    h2c->fp_str.data = ngx_pnalloc(c->pool, n);
    if (h2c->fp_str.data == NULL) {
        /** Else we break a stream */
        return NGX_ERROR;
    }
    pstr = h2c->fp_str.data;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_http2_fingerprint: alloc bytes: [%d]\n", n);

    /* setting */
    for (i = 0; i < h2c->fp_settings.len; i+=5) {
        pstr = append_uint8(pstr, h2c->fp_settings.data[i]);
        *pstr++ = ':';
        pstr = append_uint32(pstr, *(uint32_t*)(h2c->fp_settings.data+i+1));
        *pstr++ = ';';
    }
    *(pstr-1) = '|';

    /* windows update */
    pstr = append_uint32(pstr, h2c->fp_windowupdate);
    *pstr++ = '|';

    /* priorities */
    for (i = 0; i < h2c->fp_priorities.len; i+=4) {
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i]);
        *pstr++ = ':';
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i+1]);
        *pstr++ = ':';
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i+2]);
        *pstr++ = ':';
        pstr = append_uint16(pstr, (uint16_t)h2c->fp_priorities.data[i+3]+1);
        *pstr++ = ',';
    }
    *(pstr-1) = '|';

    /* fp_pseudoheaders */
    for (i = 0; i < h2c->fp_pseudoheaders.len; i++) {
        *pstr++ = h2c->fp_pseudoheaders.data[i];
        *pstr++ = ',';
    }

    /* null terminator */
    *--pstr = 0;

    h2c->fp_str.len = pstr - h2c->fp_str.data;

    h2c->fp_fingerprinted = 1;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_http2_fingerprint: http2 fingerprint: [%V], len=[%d]\n", &h2c->fp_str, h2c->fp_str.len);

    return NGX_OK;
}


static const u_char *
convert_TLS_version_to_string(uint16_t tls_version)
{
    switch (tls_version) {
    case 0x304:
        return (u_char *)"13";
    case 0x303:
        return (u_char *)"12";
    case 0x302:
        return (u_char *)"11";
    case 0x301:
        return (u_char *)"10";
    case 0x300:
        return (u_char *)"s3";
    case 0x200:
        return (u_char *)"s2";
    case 0x100:
        return (u_char *)"s1";
    case 0xfeff:
        return (u_char *)"d1";
    case 0xfefd:
        return (u_char *)"d2";
    case 0xfefc:
        return (u_char *)"d3";
    default:
        return (u_char *)"00";
    }
}


static u_char *
append_count_as_two_digit_string(u_char *dest, uint16_t count)
{
  if (count <= 9) {
    *dest++ = '0';
  }
  return append_uint16(dest, ngx_min(count, 99));
}


static int
cmp_uint16(const void *p1, const void *p2)
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
sort_uint16(uint16_t *data, size_t count)
{
    qsort(data, count, sizeof(uint16_t), cmp_uint16);
}


static uint16_t *
ja4_clean_ciphers(ngx_connection_t *c, const uint16_t *data, size_t len,
                  size_t *out_num, int original)
{
    const uint16_t  *end = (uint16_t *)((uint8_t *)data + len), *p;
    uint16_t        *values, *q;
    size_t           n = 0;

    for (p = data; p < end; p++) {
        if (!IS_GREASE_CODE(*p))
            n++;
    }

    values = ngx_pnalloc(c->pool, n * sizeof(uint16_t));
    if (values == NULL) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0, "ngx_ssl_ja4_r "
                "out of memory for cleaned ciphers");
        return NULL;
    }

    q = values;
    for (p = data; p < end; p++) {
        if (!IS_GREASE_CODE(*p))
            *q++ = ntohs(*(uint16_t *)p);
    }

    if (!original)
        sort_uint16(values, n);
    *out_num = n;
    return values;
}


static int
is_ignored_non_grease_extension(uint16_t extension)
{
    return extension == TLSEXT_TYPE_server_name
        || extension == TLSEXT_TYPE_application_layer_protocol_negotiation;
}

static int
reject_no_extension(uint16_t extension)
{
    return 0;
}

static uint16_t *
ja4_clean_extensions(ngx_connection_t *c, const uint16_t *data, size_t len,
                     size_t *out_num_exts, size_t *out_num_cleaned_exts,
                     int original)
{
    const uint16_t  *end = (uint16_t *)((uint8_t *)data + len), *p;
    uint16_t        *values, *q;
    size_t           num_exts = 0, num_cleaned_exts = 0;
    int             (*filter)(uint16_t) = original
                                        ? reject_no_extension
                                        : is_ignored_non_grease_extension;

    for (p = data; p < end; p++) {
        if (!IS_GREASE_CODE(*p)) {
            num_exts++;
            if (!filter(*p))
                num_cleaned_exts++;
        }
    }

    values = ngx_pnalloc(c->pool, num_cleaned_exts * sizeof(uint16_t));
    if (values == NULL) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0, "ngx_ssl_ja4_r "
                "out of memory for cleaned extensions");
        return NULL;
    }

    q = values;
    for (p = data; p < end; p++) {
        if (!IS_GREASE_CODE(*p) && !filter(*p))
            *q++ = *p;
    }

    if (!original)
        sort_uint16(values, num_cleaned_exts);
    *out_num_exts = num_exts;
    *out_num_cleaned_exts = num_cleaned_exts;
    return values;
}


static u_char *
append_hex_uint16(u_char *dst, const uint16_t *src, size_t count)
{
    static u_char  hex[] = "0123456789abcdef";
    const uint16_t *p, *end = src + count;
    u_char          hi, lo;

    for (p = src; p < end; p++) {
        if (p > src)
            *dst++ = ',';
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
append_hex_uint16_from_bytes(u_char *dst, const u_char *src,
		             size_t src_byte_len)
{
    static u_char  hex[] = "0123456789abcdef";
    const u_char  *p = src, *end = src + src_byte_len;
    u_char         hi, lo;

    while (p < end) {
        if (p > src)
            *dst++ = ',';

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
ngx_ssl_ja4_r_helper(ngx_connection_t *c, ngx_str_t *dest_field, int original)
{
    const u_char    *data, *first_alpn = NULL, *sig_algos = NULL;
    u_char          *ptr = NULL, sni;
    uint16_t        *ciphers_data, *exts_data;
    uint16_t         tls_version, ciphers_len, exts_len, sig_algos_len,
		     sig_algos_data_len;
    size_t           num_ciphers, num_exts, num_cleaned_exts,
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
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: fp_ja4_data == NULL");
        return NGX_ERROR;
    }

    if (dest_field->data != NULL) {
        return NGX_OK;
    }

    data = c->ssl->fp_ja4_data.data
            + sizeof(char)      /* protocol */
            + sizeof(char)      /* sni */
            + sizeof(uint16_t)  /* version */
            + sizeof(char) * 2; /* first ALPN */

    (void) ngx_copy(&ciphers_len, data, sizeof(uint16_t));
    data += sizeof(uint16_t);
    ciphers_data = ja4_clean_ciphers(c, (const uint16_t *) data, ciphers_len,
		                     &num_ciphers, original);
    if (ciphers_data == NULL) {
        dest_field->len = 0;
        return NGX_ERROR;
    }
    data += ciphers_len;

    (void) ngx_copy(&exts_len, data, sizeof(uint16_t));
    data += sizeof(uint16_t);
    exts_data = ja4_clean_extensions(c, (const uint16_t *) data, exts_len,
		                     &num_exts, &num_cleaned_exts, original);
    if (exts_data == NULL) {
        dest_field->len = 0;
        return NGX_ERROR;
    }
    data += exts_len;

    (void) ngx_copy(&sig_algos_len, data, sizeof(uint16_t));
    data += sizeof(uint16_t);
    if (sig_algos_len >= sizeof(uint16_t)) {
        sig_algos_data_len = (*data << 8) | *(data + 1); /* big endian */
        if (sig_algos_len != sig_algos_data_len + sizeof(uint16_t)) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "ngx_ssl_ja4_r_helper "
                          "sig_algos_len mismatch, outer_len=%d, "
			  "inner_len=%d, diff must be 2",
                          sig_algos_len, sig_algos_data_len);
            dest_field->len = 0;
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
                      "ngx_ssl_ja4_r_helper "
                      "end mismatch, got=%p, want=%p, original=%d",
                      data, c->ssl->fp_ja4_data.data + c->ssl->fp_ja4_data.len,
		      original);
    }

    dest_field->len = 1 /* protocol */
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
    dest_field->data = ngx_pnalloc(c->pool, dest_field->len);
    if (dest_field->data == NULL) {
        /** Else we break a data stream */
        dest_field->len = 0;
        return NGX_ERROR;
    }

    /*
     * https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
     */

    data = c->ssl->fp_ja4_data.data;

    /* protocol */
    ptr = dest_field->data;
    *ptr++ = *data++;
    sni = *data++;

    /* version */
    tls_version = *(uint16_t *)data;
    data += sizeof(uint16_t);
    ptr = ngx_copy(ptr, convert_TLS_version_to_string(tls_version), 2);

    first_alpn = data;
    data += 2;

    /* sni */
    *ptr++ = sni;

    /* number of ciphers */
    ptr = append_count_as_two_digit_string(ptr, num_ciphers);

    /* number of extensions */
    ptr = append_count_as_two_digit_string(ptr, num_exts);

    /* first ALPN */
    ptr = ngx_copy(ptr, first_alpn, 2);

    /* ciphers */
    *ptr++ = '_';
    ptr = append_hex_uint16(ptr, ciphers_data, num_ciphers);

    /* extensions */
    *ptr++ = '_';
    ptr = append_hex_uint16(ptr, exts_data, num_cleaned_exts);

    /* signature algorithms */
    if (num_sig_algos > 0) {
        *ptr++ = '_';
        ptr = append_hex_uint16_from_bytes(ptr, sig_algos, sig_algos_data_len);
    }

    return NGX_OK;
}


static int
ngx_ssl_ja4_helper(ngx_connection_t *c, ngx_str_t *raw_field,
		   ngx_str_t *dest_field, int original)
{
    u_char         hash_buf[EVP_MAX_MD_SIZE], *ptr, *src, *part_end;
    unsigned int   hash_len;
    const EVP_MD  *digest;
    EVP_MD_CTX    *ctx;
    int            ret = NGX_ERROR;

    if (dest_field->len > 0) {
        return NGX_OK;
    }

    if (ngx_ssl_ja4_r_helper(c, raw_field, original) != NGX_OK) {
        return NGX_ERROR;
    }

    dest_field->len = JA4_a_len + 1 + JA4_b_len + 1 + JA4_c_len;
    dest_field->data = ngx_pnalloc(c->pool, dest_field->len);
    if (dest_field->data == NULL) {
        /** Else we can break a stream */
        dest_field->len = 0;
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0,
                  "ngx_ssl_ja4_hash: alloc bytes: [%d]\n",
                  dest_field->len);

    /* JA4_a part */

    src = raw_field->data;
    ptr = dest_field->data;
    ptr = ngx_cpymem(ptr, src, JA4_a_len);
    *ptr++ = '_';

    ctx = EVP_MD_CTX_new();
    digest = EVP_sha256();

    /* JA4_b part */
    src += JA4_a_len + 1;
    part_end = (u_char *)ngx_strchr(src, '_');
    EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT);
    if ((EVP_DigestInit_ex(ctx, digest, NULL)
         && EVP_DigestUpdate(ctx, src, part_end - src)
         && EVP_DigestFinal_ex(ctx, hash_buf, &hash_len)) != 1)
    {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "ngx_ssl_ja4_helper "
                      "failed to digest JA4_b");
        goto failed;
    }
    ngx_hex_dump(ptr, hash_buf, JA4_b_len / 2);
    ptr += JA4_b_len;
    *ptr++ = '_';

    /* JA4_c part */
    src = part_end + 1;
    part_end = raw_field->data + raw_field->len;
    if (part_end == src) {
        (void) ngx_copy(ptr, "000000000000", JA4_c_len);
    } else {
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT);
        if ((EVP_DigestInit_ex(ctx, digest, NULL)
             && EVP_DigestUpdate(ctx, src, part_end - src)
             && EVP_DigestFinal_ex(ctx, hash_buf, &hash_len)) != 1)
        {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "ngx_ssl_ja4_helper "
                          "failed to digest JA4_c");
            goto failed;
        }
        ngx_hex_dump(ptr, hash_buf, JA4_c_len / 2);
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
ngx_ssl_ja4_r(ngx_connection_t *c)
{
    return ngx_ssl_ja4_r_helper(c, &c->ssl->fp_ja4_r, 0);
}


/**
 * Params:
 *      c and c->ssl should be valid pointers and tested before.
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja4 is alread set
 *      NGX_ERROR - something went wrong
 */
int ngx_ssl_ja4(ngx_connection_t *c)
{
    return ngx_ssl_ja4_helper(c, &c->ssl->fp_ja4_r, &c->ssl->fp_ja4, 0);
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
ngx_ssl_ja4_ro(ngx_connection_t *c)
{
    return ngx_ssl_ja4_r_helper(c, &c->ssl->fp_ja4_ro, 1);
}


/**
 * Params:
 *      c and c->ssl should be valid pointers and tested before.
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja4_o is alread set
 *      NGX_ERROR - something went wrong
 */
int ngx_ssl_ja4_o(ngx_connection_t *c)
{
    return ngx_ssl_ja4_helper(c, &c->ssl->fp_ja4_ro, &c->ssl->fp_ja4_o, 1);
}
