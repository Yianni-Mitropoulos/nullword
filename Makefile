CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wno-unused-result
LDFLAGS := -largon2 -lssl -lcrypto -Wl,-z,relro,-z,now
BIN     := twain
SRC     := twain.c
CLIPBIN := twain-clip
CLIPSRC := twain-clip.c

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin

.PHONY: all clean install uninstall

all: $(BIN) $(CLIPBIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

$(CLIPBIN): $(CLIPSRC)
	$(CC) $(CFLAGS) $< -o $@

install: $(BIN) $(CLIPBIN)
	install -m 755 $(BIN) $(BINDIR)/$(BIN)
	install -m 755 $(CLIPBIN) $(BINDIR)/$(CLIPBIN)

uninstall:
	rm -f $(BINDIR)/$(BIN)
	rm -f $(BINDIR)/$(CLIPBIN)

clean:
	rm -f $(BIN) $(CLIPBIN)
