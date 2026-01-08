#include "../inc/chat_room.h"

#include <memory.h>
#include <stdlib.h>
#include <string.h>
struct chat_room {
  chat *cht;
  char room_name[100];
  int name_size;
  int chat_max_size;
  int chat_index;
};

struct room_manager {
  struct chat_room *room;
  int room_size;
};

struct room_manager *manager;

int alloc_size(struct chat_room *room);

void add_chat(struct chat_room *room, const chat *msg);

chat *get_chat(const char *chat_room_name) {
  for (int i = 0; i < manager->room_size; ++i) {
    if (strncmp(manager->room[i].room_name, chat_room_name,
                manager->room[i].name_size) == 0) {
      return manager->room[i].cht;
    }
  }
  return (chat *)NULL;
};

int add_chat_by_room(const char *chat_room_name, const chat *msg) {
  for (int i = 0; i < manager->room_size; ++i) {
    if (strncmp(manager->room[i].room_name, chat_room_name,
                manager->room[i].name_size)) {
      if (alloc_size(&(manager->room[i])) == -1) {
      }
      add_chat(&(manager->room[i]), msg);
    }
  }
  return -1;
};

void add_chat(struct chat_room *room, const chat *msg) {
  int index = room->chat_index, msg_size = msg->msg_size;
  index++;
  room->cht[index].msg = (char *)malloc(sizeof(char) * msg_size);
  room->cht[index].msg_size = msg_size;
  room->cht[index].usr = (char *)malloc(sizeof(char) * msg->name_size);
  room->cht[index].name_size = msg->name_size;
  room->chat_index++;
  strncpy(room->cht[index].msg, msg->usr, msg->name_size);
  strncpy(room->cht[index].msg, msg->msg, msg->msg_size);
};
int alloc_size(struct chat_room *room) {
  if (room->chat_index >= (room->chat_max_size - 100)) {
    int re_size = sizeof(chat) * (room->chat_max_size + 200);
    room->cht = realloc(room->cht, re_size);
    /// if realloc 실패시 return -1;
  }
  return 0;
};
