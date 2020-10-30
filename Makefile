CC=gcc
CCOPTS=-W -Wall -O2 -fPIC -Wno-strict-aliasing
LDOPTS=-s -pie

all: unstream

%: %.c
	$(CC) $(CCOPTS) -o $@ $+ $(LDOPTS)

clean:
	rm -f *.o
