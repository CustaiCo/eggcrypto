# Makefile for src/mod/crypto.mod/
# $Id: Makefile,v 1.15 2011/07/09 15:07:48 thommey Exp $

srcdir = .


doofus:
	@echo ""
	@echo "Let's try this from the right directory..."
	@echo ""
	@cd ../../../ && make

static: ../crypto.o

modules: ../../../crypto.$(MOD_EXT)

../crypto.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -DMAKING_MODS -c $(srcdir)/crypto.c
	@rm -f ../crypto.o
	mv crypto.o ../

../../../crypto.$(MOD_EXT): ../crypto.o
	$(LD) -o ../../../crypto.$(MOD_EXT) ../crypto.o $(XLIBS) $(MODULE_XLIBS)
	$(STRIP) ../../../crypto.$(MOD_EXT)

depend:
	$(CC) $(CFLAGS) -MM $(srcdir)/crypto.c -MT ../crypto.o > .depend

clean:
	@rm -f .depend *.o *.$(MOD_EXT) *~

distclean: clean

#safety hash
../crypto.o: crypto.c ../../../src/mod/module.h ../../../src/main.h \
 ../../../config.h ../../../lush.h ../../../src/lang.h \
 ../../../src/eggdrop.h ../../../src/flags.h ../../../src/cmdt.h \
 ../../../src/tclegg.h ../../../src/tclhash.h ../../../src/chan.h \
 ../../../src/users.h ../../../src/compat/compat.h \
 ../../../src/compat/inet_aton.h ../../../src/compat/snprintf.h \
 ../../../src/compat/memset.h ../../../src/compat/memcpy.h \
 ../../../src/compat/strcasecmp.h ../../../src/compat/strdup.h \
 ../../../src/compat/strftime.h ../../../src/mod/modvals.h \
 ../../../src/tandem.h ../../../src/mod/irc.mod/irc.h \
 ../../../src/mod/server.mod/server.h tweetnacl.h crypto.h
