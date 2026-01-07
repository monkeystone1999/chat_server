#ifndef THR_POOL_H
#define THR_POOL_H

typedef struct pool_context pool_context;
typedef void *(*thr_ptr_t)(void *arg);
int resize_pools(int poolSize);
void *get_result(pool_context *ctx, int eventfd);
int ctx_run(pool_context *ctx);
int throw_work(pool_context *ctx, thr_ptr_t func, void *arg);

pool_context *create_pool_ctx(int poolSize);
#endif
