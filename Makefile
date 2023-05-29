CFLAGS += -std=c11 -Wall -D_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64 -fPIC -flto -O3
LFLAGS += -fPIC -flto

all: checkmd5
	strip checkmd5
clean:
	rm -f *.o
	rm -f checkmd5

checkmd5: checkmd5.o md5.o
	$(CC) $(LFLAGS) checkmd5.o md5.o -o checkmd5
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
