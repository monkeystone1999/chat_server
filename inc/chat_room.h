#ifndef CHAT_ROOM_H_
#define CHAT_ROOM_H_

typedef struct {
  char *msg, *usr;
  int msg_size, name_size;
} chat;
int add_chat_by_room(const char *chat_room_name, const chat *msg);
#endif
