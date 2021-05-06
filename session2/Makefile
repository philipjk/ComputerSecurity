LDLIBS=-lssl -lcrypto
CFLAGS=-Wall -pedantic

PROGS=des_enc des_dec

all: $(PROGS)
	
clean:
	rm -f *~ *.bin *.bak $(PROGS)

clean-keys:
	rm -f *.pem *.der

run:
	./des_enc 
	./des_dec
