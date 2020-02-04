CC           = clang
CFLAGS       = -Wall -Wextra -Wpedantic -fsanitize=undefined -O2

OBJ = main.o crypto-hex.o crypto-base64.o crypto-aes256.o \
	crypto-sha256.o crypto-sha256-hmac.o crypto-sha256-hkdf.o

all: whats-dec

%.o: %.c *.h
	$(CC) $(CFLAGS) -c $< -o $@

whats-dec: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS) $(LIBS)

clean:
	rm -f whats-dec *.o

test: whats-dec
	./whats-dec --test
