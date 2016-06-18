CC=gcc
GPP=g++
CFLAGS=-ggdb
ODIR=obj
SDIR=src
OUT=out

all: reaper

_OBJS = reaper.o protocol.o socketio.o
OBJS = $(patsubst %,$(ODIR)/%,$(_OBJS))

reaper: pre $(OBJS)
	$(CC) -o $(OUT)/$@ $(OBJS)

$(ODIR)/%.o: $(SDIR)/%.c 
	$(CC) -c -o $@ $< $(CFLAGS) 

pre:
	test -d $(ODIR) || mkdir $(ODIR)
	test -d $(OUT) || mkdir $(OUT)

clean:
	rm -rf $(OBJS) reaper
