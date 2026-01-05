#include "../inc/thread_pool.h"
#include <memory.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>
typedef struct {
  void *arg;
  pthread_func func;
  int event_fd;
  bool working;
  void *result;
  bool thread_shutdown;
  pthread_mutex_t m;
  pthread_t th_t;
} thread_pool;

struct pool_context {
  thread_pool *thread_pools;
  int pool_size;
};

void *thread_func(void *arg);
pool_context *create_pool_ctx(int poolSize) {
  pool_context *ctx = (pool_context *)malloc(sizeof(pool_context));
  ctx->pool_size = poolSize;
  ctx->thread_pools =
      (thread_pool *)malloc(sizeof(thread_pool) * ctx->pool_size);
  for (int i = 0; i < poolSize; ++i) {
    ctx->thread_pools[i].event_fd = eventfd(0, EFD_CLOEXEC);
    ctx->thread_pools[i].working = false;
    ctx->thread_pools[i].thread_shutdown = false;
    pthread_mutex_init(&ctx->thread_pools[i].m, NULL);
  }
  return ctx;
}
/// ctx 가 존재하고 해당 pool size 를 조정하는것
int resize_pools_ctx(pool_context *ctx, int poolSize) {
  if (ctx->pool_size == poolSize) {
    return 0;
  }
  ctx->thread_pools =
      realloc(ctx->thread_pools, sizeof(thread_pool) * poolSize);
  ctx->pool_size = poolSize;
  return 1;
}

void *get_result(pool_context *ctx, int eventfd) {
  pool_context *t_ctx = ctx;
  for (int i = 0; i < t_ctx->pool_size; ++i) {
    if (t_ctx->thread_pools[i].event_fd == eventfd) {
      if (t_ctx->thread_pools[i].working == true) {
        return (void *)NULL;
      }
      return t_ctx->thread_pools[i].result;
    }
  }
}

int ctx_run(pool_context *ctx) {
  pool_context *t_ctx = ctx;
  for (int i = 0; i < t_ctx->pool_size; ++i) {
    pthread_t th;
    ctx->thread_pools[i].th_t = th;
    pthread_create(&th, 0, thread_func, &(ctx->thread_pools[i]));
  }
  return 0;
}

int check_working(pool_context *ctx) {
  pool_context *t_ctx = ctx;
  int not_work_thread = -1;
  for (int i = 0; i < t_ctx->pool_size; ++i) {
    pthread_mutex_lock(&t_ctx->thread_pools[i].m);
    if (t_ctx->thread_pools[i].working == false) {
      not_work_thread = i;
      pthread_mutex_unlock(&t_ctx->thread_pools[i].m);
      break;
    }
    pthread_mutex_unlock(&t_ctx->thread_pools[i].m);
  }
  return not_work_thread;
}

int throw_work(pool_context *ctx, pthread_func func, void *arg) {
  int index = check_working(ctx);
  if (index == -1) {
    return -1;
  }
  pthread_mutex_lock(&ctx->thread_pools[index].m);
  ctx->thread_pools[index].func = func;
  ctx->thread_pools[index].arg = arg;
  ctx->thread_pools[index].working = true;
  pthread_mutex_unlock(&ctx->thread_pools[index].m);
  uint64_t val = 1;
  write(ctx->thread_pools[index].event_fd, &val, sizeof(uint64_t));
  return ctx->thread_pools[index].event_fd;
}

void *thread_func(void *arg) {
  thread_pool *man = (thread_pool *)arg;
  int eventfd = man->event_fd;
  uint64_t readSome;
  while (1) {
    read(eventfd, &readSome, sizeof(uint64_t));
    if (man->thread_shutdown) {
      break;
    }
    man->result = man->func(man->arg);
    pthread_mutex_lock(&man->m);
    man->working = false;
    pthread_mutex_unlock(&man->m);
  }
  return man->result;
}

int free_ctx(pool_context *ctx) {
  pool_context *t_ctx = ctx;
  uint64_t val = 1;
  for (int i = 0; i < t_ctx->pool_size; ++i) {
    pthread_mutex_lock(&ctx->thread_pools[i].m);
    ctx->thread_pools[i].thread_shutdown = true;
    pthread_mutex_unlock(&ctx->thread_pools[i].m);
    write(ctx->thread_pools[i].event_fd, &val, sizeof(uint64_t));
  }
  for (int i = 0; i < t_ctx->pool_size; ++i) {
    pthread_join(ctx->thread_pools[i].th_t, NULL);
  }
  for (int i = 0; i < t_ctx->pool_size; ++i) {
    close(t_ctx->thread_pools[i].event_fd);
    pthread_mutex_destroy(&ctx->thread_pools[i].m);
  }
  free(ctx->thread_pools);
  free(ctx);
  return 1;
}
