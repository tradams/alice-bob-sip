top_srcdir = .
prefix = /home/tra26/karma/local
exec_prefix = ${prefix}
libdir = ${exec_prefix}/lib
includedir = ${prefix}/include

CC = gcc
CFLAGS  = -I/home/tra26/karma/local/include -I/home/tra26/karma/local/include -DPACKAGE_NAME=\"libpaillier\" -DPACKAGE_TARNAME=\"libpaillier\" -DPACKAGE_VERSION=\"0.8\" -DPACKAGE_STRING=\"libpaillier\ 0.8\" -DPACKAGE_BUGREPORT=\"bethenco@cs.berkeley.edu\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_STDLIB_H=1 -DHAVE_MALLOC=1 -DHAVE_STDLIB_H=1 -DHAVE_REALLOC=1 -DHAVE_MEMSET=1 -DHAVE_GMP=1
LDFLAGS = -L/home/tra26/karma/local/lib  -L/home/tra26/karma/local/lib -lgmp -L/lib -lgmp -L/var/lib -lgmp 

DISTNAME = libpaillier-0.8

all: libpaillier.a TAGS

# compilation and library making

libpaillier.a: paillier.o
	rm -f $@
	ar rc $@ $<

test: test.o libpaillier.a
	$(CC) -o $@ $(LDFLAGS) $^

perf: perf.o libpaillier.a
	$(CC) -o $@ $(LDFLAGS) $^

%.o: %.c *.h Makefile
	$(CC) -c -o $@ $< $(CFLAGS)

# installation

dist: AUTHORS COPYING INSTALL Makefile.in NEWS README aclocal.m4 \
	paillier.c paillier.h configure configure.ac install-sh m4 missing mkinstalldirs
	rm -rf $(DISTNAME)
	mkdir $(DISTNAME)
	cp -r $^ $(DISTNAME)
	rm -rf $(DISTNAME)/m4/.svn $(DISTNAME)/m4/*~
	tar zc $(DISTNAME) > $(DISTNAME).tar.gz
	rm -rf $(DISTNAME)

install: libpaillier.a paillier.h
	$(top_srcdir)/mkinstalldirs -m 755 $(libdir)
	$(top_srcdir)/mkinstalldirs -m 755 $(includedir)
	$(top_srcdir)/install-sh -m 755 libpaillier.a $(libdir)
	$(top_srcdir)/install-sh -m 644 paillier.h $(includedir)

uninstall:
	/bin/rm -f $(libdir)/libpaillier.a
	/bin/rm -f $(includedir)/paillier.h

# development and meta stuff

TAGS: *.c *.h
	@(etags $^ || true) 2> /dev/null

Makefile: Makefile.in config.status
	./config.status

config.status: configure
	./config.status --recheck

configure: configure.ac aclocal.m4
	autoconf

# cleanup

# remove everything an installing user can rebuild
clean:
	rm -rf *.o *.a perf $(DISTNAME) *.tar.gz TAGS *~

# remove everything a package developer can rebuild
distclean: clean
	rm -rf autom4te.cache Makefile config.status config.log config.cache \
		configure configure.scan autoscan.log
