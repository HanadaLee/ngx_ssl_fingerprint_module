/*
 * Copyright (C) Hanada
 */


#ifndef _NGX_TEST_MD5_H_INCLUDED_
#define _NGX_TEST_MD5_H_INCLUDED_


#include <ngx_config.h>


typedef MD5_CTX  ngx_md5_t;

#define ngx_md5_init(ctx)            MD5_Init(ctx)
#define ngx_md5_update(ctx, p, n)    MD5_Update((ctx), (p), (n))
#define ngx_md5_final(out, ctx)      MD5_Final((out), (ctx))


#endif /* _NGX_TEST_MD5_H_INCLUDED_ */
