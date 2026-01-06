#ifndef THR_POOL_H
#define THR_POOL_H

typedef struct pool_context pool_context;
typedef void *(*pthread_func)(void *arg);
int resize_pools(int poolSize);
void *get_result(pool_context *ctx, int eventfd);
int ctx_run(pool_context *ctx);
int throw_work(pool_context *ctx, pthread_func func, void *arg);

pool_context *create_pool_ctx(int poolSize);
#endif
