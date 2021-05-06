LDLIBS=-lssl -lcrypto
CFLAGS=-Wall -pedantic

PROGS=encrypt decrypt

all: $(PROGS)
	
keys:
	openssl genrsa -out sk.pem 2048
	openssl rsa -inform pem -in sk.pem -RSAPublicKey_out -out pk.pem
	# turn into binary format
	# openssl -inform pem -in sk.pem -outform der -out sk.der

clean:
	rm -f *~ *.bin *.bak $(PROGS)

clean-keys:
	rm -f *.pem *.der

run:
	./encrypt pk.pem Ciaone! ciphered.bin
	./decrypt sk.pem ciphered.bin
