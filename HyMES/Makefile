CC= gcc
CFLAGS=  -g -O4
CPPFLAGS =

TARGETS = mce keygen encrypt decrypt

all: $(TARGETS)

mce: keypair.o encrypt.o decrypt.o randomize.o poly.o gf.o mat.o arith.o buff.o dicho.o cwdata.o main_mce.o
	$(CC) $(CFLAGS) keypair.o encrypt.o decrypt.o randomize.o poly.o gf.o mat.o arith.o buff.o dicho.o cwdata.o main_mce.o -lm -o mce

keygen: keypair.o poly.o gf.o mat.o main_keygen.o
	$(CC) $(CFLAGS) keypair.o poly.o gf.o mat.o main_keygen.o -o keygen

encrypt: encrypt.o randomize.o arith.o buff.o dicho.o cwdata.o main_encrypt.o
	$(CC) $(CFLAGS) encrypt.o randomize.o arith.o buff.o dicho.o cwdata.o main_encrypt.o -lm -o encrypt

decrypt: decrypt.o randomize.o poly.o gf.o arith.o buff.o dicho.o cwdata.o main_decrypt.o
	$(CC) $(CFLAGS) decrypt.o randomize.o poly.o gf.o arith.o buff.o dicho.o cwdata.o main_decrypt.o -lm -o decrypt

genparams: precomp.o workfactor.o main_genparams.o
	$(CC) $(CFLAGS) precomp.o workfactor.o main_genparams.o -lm -o genparams

cwinfo: precomp.o main_cwinfo.o
	$(CC) $(CFLAGS) precomp.o main_cwinfo.o -lm -o cwinfo

cwinfo_full: precomp.o main_cwinfo_full.o
	$(CC) $(CFLAGS) precomp.o main_cwinfo_full.o -lm -o cwinfo_full

main_cwinfo_full.o: main_cwinfo.c
	$(CC) $(CPPFLAGS) -DFULL $(CFLAGS) -c -o main_cwinfo_full.o main_cwinfo.c

secinfo: workfactor.o main_secinfo.o
	$(CC) $(CFLAGS) workfactor.o main_secinfo.o -lm -o secinfo

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

depend:
	makedepend *.c

clean:
	- /bin/rm *.o

veryclean: clean
	- /bin/rm $(TARGETS) genparams cwinfo secinfo cwdata.c params.h


