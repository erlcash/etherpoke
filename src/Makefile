CC = gcc
CFLAGS = -O2 -std=gnu99 -pedantic -ggdb

NAME = etherpoke
INSTALL_DIR = /usr/local/bin

.PHONY: clean install

all: $(NAME)

$(NAME): main.o clocker.o config.o executioner.o listener.o log.o metapkt.o queue.o session.o
	$(CC) $(CFLAGS) $^ -o $(NAME) -lpcap -lpthread -lconfig

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

clocker.o: clocker.c
	$(CC) $(CFLAGS) -c clocker.c

config.o: config.c
	$(CC) $(CFLAGS) -c config.c

executioner.o: executioner.c
	$(CC) $(CFLAGS) -c executioner.c

listener.o: listener.c
	$(CC) $(CFLAGS) -c listener.c

log.o: log.c
	$(CC) $(CFLAGS) -c log.c

metapkt.o: metapkt.c
	$(CC) $(CFLAGS) -c metapkt.c

queue.o: queue.c
	$(CC) $(CFLAGS) -c queue.c

session.o: session.c
	$(CC) $(CFLAGS) -c session.c

install: $(NAME)
	install -m 755 $(NAME) $(INSTALL_DIR)

clean:
	rm -f *.o $(NAME)

