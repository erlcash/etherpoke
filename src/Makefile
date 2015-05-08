CC = gcc
CFLAGS = -std=gnu99 -O2 -pedantic -Wall -ggdb

NAME = etherpoke
INSTALL_DIR = /usr/local/sbin

.PHONY: clean install

all: $(NAME)

install: $(NAME)
	install --mode 755 $(NAME) $(INSTALL_DIR)
	#setcap cap_net_raw,cap_net_admin=eip $(INSTALL_DIR)/$(NAME)

uninstall:
	rm -f $(INSTALL_DIR)/$(NAME)

clean:
	rm -f *.o $(NAME)

$(NAME): main.o config.o session_data.o sock.o
	$(CC) $(CFLAGS) $^ -o $(NAME) -lpcap -lconfig

main.o: main.c
	$(CC) $(CFLAGS) -c $<

config.o: config.c config.h
	$(CC) $(CFLAGS) -c $<

session_data.o: session_data.c session_data.h
	$(CC) $(CFLAGS) -c $<

sock.o: sock.c sock.h
	$(CC) $(CFLAGS) -c $<

