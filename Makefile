# FreeBSD Makefile for isolate
CC = clang
CFLAGS = -Wall -Wextra -std=c99 -O2 -Isrc
LDFLAGS = -ljail
PREFIX = /usr/local

# Build directories
SRCDIR = src
OBJDIR = obj
BINDIR = bin
EXAMPLEDIR = examples

TARGET = ${BINDIR}/isolate
OBJECTS = ${OBJDIR}/main.o ${OBJDIR}/caps.o ${OBJDIR}/isolation.o ${OBJDIR}/freebsd.o

# Example programs
EXAMPLES = ${EXAMPLEDIR}/hello ${EXAMPLEDIR}/server

all: directories ${TARGET} ${EXAMPLES}

directories:
	@mkdir -p ${OBJDIR} ${BINDIR}

${TARGET}: ${OBJECTS}
	${CC} ${CFLAGS} -o ${TARGET} ${OBJECTS} ${LDFLAGS}

${OBJDIR}/main.o: ${SRCDIR}/main.c ${SRCDIR}/common.h
	${CC} ${CFLAGS} -c ${SRCDIR}/main.c -o ${OBJDIR}/main.o

${OBJDIR}/caps.o: ${SRCDIR}/caps.c ${SRCDIR}/common.h
	${CC} ${CFLAGS} -c ${SRCDIR}/caps.c -o ${OBJDIR}/caps.o

${OBJDIR}/isolation.o: ${SRCDIR}/isolation.c ${SRCDIR}/common.h
	${CC} ${CFLAGS} -c ${SRCDIR}/isolation.c -o ${OBJDIR}/isolation.o

${OBJDIR}/freebsd.o: ${SRCDIR}/freebsd.c ${SRCDIR}/common.h
	${CC} ${CFLAGS} -c ${SRCDIR}/freebsd.c -o ${OBJDIR}/freebsd.o

# Example programs
${EXAMPLEDIR}/hello: ${EXAMPLEDIR}/hello.c
	${CC} -o ${EXAMPLEDIR}/hello ${EXAMPLEDIR}/hello.c

${EXAMPLEDIR}/server: ${EXAMPLEDIR}/server.c
	${CC} -o ${EXAMPLEDIR}/server ${EXAMPLEDIR}/server.c

clean:
	rm -rf ${OBJDIR} ${BINDIR}
	rm -f ${EXAMPLES}

distclean: clean
	rm -rf ${OBJDIR} ${BINDIR}

install: ${TARGET}
	install -d ${PREFIX}/bin
	install -m 755 ${TARGET} ${PREFIX}/bin/
	install -d ${PREFIX}/share/isolate/examples
	install -m 644 ${EXAMPLEDIR}/*.caps ${PREFIX}/share/isolate/examples/
	install -m 755 ${EXAMPLES} ${PREFIX}/share/isolate/examples/

test: ${TARGET} ${EXAMPLES}
	@echo "Running basic test..."
	doas ${TARGET} -v ${EXAMPLEDIR}/hello
	@echo "Test completed successfully"

test-server: ${TARGET} ${EXAMPLES}
	@echo "Starting TCP server test (Ctrl+C to stop)..."
	doas ${TARGET} -v ${EXAMPLEDIR}/server

debug: CFLAGS += -g -DDEBUG
debug: clean all

release: CFLAGS += -O3 -DNDEBUG
release: clean all

.PHONY: all directories clean distclean install test test-server debug release
