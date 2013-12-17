NAME = etherpoke
BINDIR = ../bin
INSTALLDIR = /usr/local/bin

all: $(BINDIR)/$(NAME)

$(BINDIR)/$(NAME): clocker.o config.o executioner.o listener.o log.o metapkt.o queue.o session.o
	gcc *.c -o $(BINDIR)/$(NAME) -lpcap -lpthread -lconfig

clocker.o: clocker.c
	gcc -ggdb -O0 -c clocker.c

config.o: config.c
	gcc -ggdb -O0 -c config.c

executioner.o: executioner.c
	gcc -ggdb -O0 -c executioner.c

listener.o: listener.c
	gcc -ggdb -O0 -c listener.c

log.o: log.c
	gcc -ggdb -O0 -c log.c

metapkt.o: metapkt.c
	gcc -ggdb -O0 -c metapkt.c

queue.o: queue.c
	gcc -ggdb -O0 -c queue.c

session.o: session.c
	gcc -ggdb -O0 -c session.c

install: $(BINDIR)/$(NAME)
	install -m 755 $(BINDIR)/$(NAME) $(INSTALLDIR)

clean:
	rm -f $(BINDIR)/$(NAME)
	rm -f *.o
