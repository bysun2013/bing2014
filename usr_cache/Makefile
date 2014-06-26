CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -I../include
CFLAGS += -D_GNU_SOURCE # required for glibc >= 2.8
PROGRAMS = ietd_cache ietadm_cache
LIBS =

all: $(PROGRAMS)

ietd_cache: ietd_cache.o log.o message.o  ctldev.o event.o plain.o
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)

ietadm_cache: ietadm_cache.o 
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f *.o $(PROGRAMS)
