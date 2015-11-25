#
# Copyright (c) 2013 - 2015, CodeWard.org
#

all:
	$(MAKE) -C src/

install:
	$(MAKE) -C src/ $@

uninstall:
	$(MAKE) -C src/ $@

clean:
	$(MAKE) -C src/ $@

