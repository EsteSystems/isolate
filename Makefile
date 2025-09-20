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

# Disable object directory to avoid path issues
# with BSD make
.OBJDIR: ./

TARGET = ${BINDIR}/isolate
OBJECTS = ${OBJDIR}/main.o ${OBJDIR}/caps.o ${OBJDIR}/isolation.o ${OBJDIR}/freebsd.o ${OBJDIR}/detect.o

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

${OBJDIR}/detect.o: ${SRCDIR}/detect.c ${SRCDIR}/common.h
	${CC} ${CFLAGS} -c ${SRCDIR}/detect.c -o ${OBJDIR}/detect.o

# Example programs
${EXAMPLEDIR}/hello: ${EXAMPLEDIR}/hello.c
	${CC} -o ${EXAMPLEDIR}/hello ${EXAMPLEDIR}/hello.c

${EXAMPLEDIR}/server: ${EXAMPLEDIR}/server.c
	${CC} -o ${EXAMPLEDIR}/server ${EXAMPLEDIR}/server.c

clean:
	rm -rf ${OBJDIR} ${BINDIR}
	rm -f ${EXAMPLES}
	rm -f ${EXAMPLEDIR}/*.caps

distclean: clean
	rm -rf ${OBJDIR} ${BINDIR}

install: ${TARGET}
	install -d ${PREFIX}/bin
	install -m 755 ${TARGET} ${PREFIX}/bin/
	install -d ${PREFIX}/share/isolate/examples
	install -m 644 ${EXAMPLEDIR}/*.caps ${PREFIX}/share/isolate/examples/ 2>/dev/null || true
	install -m 755 ${EXAMPLES} ${PREFIX}/share/isolate/examples/

test: ${TARGET} ${EXAMPLES}
	@echo "Running basic test..."
	doas ${TARGET} -v ${EXAMPLEDIR}/hello
	@echo "Test completed successfully"

test-server: ${TARGET} ${EXAMPLES}
	@echo "Starting TCP server test (Ctrl+C to stop)..."
	doas ${TARGET} -v ${EXAMPLEDIR}/server

test-detect: ${TARGET} ${EXAMPLES}
	@echo "Testing capability detection..."
	${TARGET} -d ${EXAMPLEDIR}/hello
	@echo "Generated capability file:"
	@cat ${EXAMPLEDIR}/hello.caps
	@echo ""
	@echo "Testing with detected capabilities..."
	doas ${TARGET} -v ${EXAMPLEDIR}/hello
	@echo "Detection test completed successfully"

debug: CFLAGS += -g -DDEBUG
debug: clean all

release: CFLAGS += -O3 -DNDEBUG
release: clean all

help:
	@echo "Isolate Build System"
	@echo "===================="
	@echo ""
	@echo "Targets:"
	@echo "  all           Build isolate and examples (default)"
	@echo "  clean         Remove build artifacts"
	@echo "  distclean     Remove all generated files"
	@echo "  install       Install to system (requires root)"
	@echo "  test          Run basic functionality test"
	@echo "  test-server   Run TCP server test"
	@echo "  test-detect   Test capability detection"
	@echo "  debug         Build with debug symbols"
	@echo "  release       Build optimized release"
	@echo "  help          Show this help"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make all                    # Build everything"
	@echo "  make test-detect           # Test detection features"
	@echo "  make clean && make debug   # Clean debug build"

.PHONY: all directories clean distclean install test test-server test-detect debug release help
