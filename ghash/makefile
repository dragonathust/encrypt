CFLAGS = -I.
LDFLAGS = -L.
LIBS = -lcrypto

all:ghash aes128gcm aes128gcm-decrypt aes256gcm aes256gcm-decrypt

ghash:ghash.c
	gcc -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LIBS)

aes128gcm:aes128gcm.c
	gcc -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LIBS)

aes128gcm-decrypt:aes128gcm-decrypt.c
	gcc -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LIBS)

aes256gcm:aes256gcm.c
	gcc -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LIBS)

aes256gcm-decrypt:aes256gcm-decrypt.c
	gcc -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LIBS)

clean:
	rm -rf *.o ghash aes128gcm aes128gcm-decrypt aes256gcm aes256gcm-decrypt

