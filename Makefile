CFLAGS = -Wall -fPIC --shared -g -O2
CC = gcc
INCLUDE_FLAGS = -I/usr/local/tsar/devel -I/opt/tsar/devel
LINK = $(CC) $(INCLUDE_FLAGS) $(CFLAGS)


OBJS =  mod_bkb.so

all: $(OBJS)

$(OBJS): %.so: mod_bkb.c cJSON.c
	$(LINK) $^ -o $@
clean:
	rm -f *.so;
install:
	mkdir -p /etc/tsar/conf.d/
	cp ./mod_bkb.so /usr/local/tsar/modules/
	cp ./mod_bkb.conf /etc/tsar/conf.d/bkb.conf
uninstall:
	rm /usr/local/tsar/modules/mod_bkb.so
	rm /etc/tsar/conf.d/bkb.conf
