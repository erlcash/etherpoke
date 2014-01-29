NAME = etherpoke
BINDIR = ../bin
INSTALLDIR = /usr/local/bin

all: $(BINDIR)/$(NAME)

$(BINDIR)/$(NAME): etherpoke.o clocker.o config.o executioner.o listener.o log.o metapkt.o queue.o session.o
	gcc *.c -o $(BINDIR)/$(NAME) -ggdb -lpcap -lpthread -lconfig

etherpoke.o: etherpoke.c
	gcc -c etherpoke.c

clocker.o: clocker.c
	gcc -c clocker.c

config.o: config.c
	gcc -c config.c

executioner.o: executioner.c
	gcc -c executioner.c

listener.o: listener.c
	gcc -c listener.c

log.o: log.c
	gcc -c log.c

metapkt.o: metapkt.c
	gcc -c metapkt.c

queue.o: queue.c
	gcc -c queue.c

session.o: session.c
	gcc -c session.c

install: $(BINDIR)/$(NAME)
	install -m 755 $(BINDIR)/$(NAME) $(INSTALLDIR)

clean:
	rm -f $(BINDIR)/$(NAME)
	rm -f *.o
