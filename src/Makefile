CC = gcc
CFLAGS = -std=gnu99 -O2 -pedantic -ggdb

NAME = etherpoke
INSTALL_DIR = /usr/local/bin

.PHONY: clean install

all: $(NAME)

$(NAME): main.o config.o
	$(CC) $(CFLAGS) $^ -o $(NAME) -lpcap -lconfig

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

config.o: config.c
	$(CC) $(CFLAGS) -c config.c

install: $(NAME)
	install -m 755 $(NAME) $(INSTALL_DIR)

clean:
	rm -f *.o $(NAME)

