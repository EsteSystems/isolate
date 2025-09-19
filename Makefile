CC = cc
CFLAGS = -Wall -Wextra -std=c99 -O2
PREFIX = /usr/local

# Detect platform
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),FreeBSD)
    PLATFORM_SRC = freebsd.c
    CFLAGS += -D__FreeBSD__
endif
ifeq ($(UNAME_S),Linux)
    PLATFORM_SRC = linux.c
    CFLAGS += -D__linux__
endif

SOURCES = main.c caps.c isolation.c $(PLATFORM_SRC)
OBJECTS = $(SOURCES:.c=.o)
TARGET = isolate

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c common.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJECTS) $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) $(PREFIX)/bin/
	install -m 644 examples/*.caps $(PREFIX)/share/isolate/

test: $(TARGET)
	@echo "Building test programs..."
	@echo '#include <stdio.h>' > hello.c
	@echo 'int main() { printf("Hello, isolated world!\\n"); return 0; }' >> hello.c
	$(CC) -o hello hello.c
	@echo "Running isolated hello world..."
	./$(TARGET) -v ./hello
	@rm -f hello hello.c

.PHONY: all clean install test
