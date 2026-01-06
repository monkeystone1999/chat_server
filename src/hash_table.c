#include "../inc/hash_table.h"

#define DEFAULT_CAPACITY 16
#define MAX_FACTOR 0.75

typedef struct hash_array {
  void *key, *value;
  struct hash_array *next;
};

struct hash_table {
  hash_array *arr;
  int *size;
};
