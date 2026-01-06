
CC:=aarch64-linux-gnu-gcc
TARGET:=chat_server
LDLIB:= src/crypt_service.c

.PHONY : LIB $(TARGET)

$(TARGET): main.o src/server.o

