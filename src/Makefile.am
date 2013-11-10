CC = gcc
CFLAGS = -Wall
AM_LDFLAGS = -lpcap -lpthread -lconfig

NAME = etherpoke

bin_PROGRAMS = $(NAME)
etherpoke_SOURCES = etherpoke.c \
					config.c \
					config.h \
					executioner.c \
					executioner.h \
					listener.c \
					listener.h \
					worker.c \
					worker.h \
					queue.c \
					queue.h

clean-local:
	rm -f $(NAME)
