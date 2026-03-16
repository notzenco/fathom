CC      ?= cc
CFLAGS  := -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE \
           $(shell pkg-config --cflags capstone 2>/dev/null)
LDFLAGS :=
LIBS    := $(shell pkg-config --libs capstone 2>/dev/null) -lrt

# Development build: enable sanitizers
ifdef ASAN
  CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
  LDFLAGS += -fsanitize=address,undefined
endif

# Debug / Release
ifdef DEBUG
  CFLAGS += -O0 -g3 -DFATHOM_DEBUG
else
  CFLAGS += -O2 -g
endif

# ── Sources ───────────────────────────────────────────────────────────

LIB_SRCS := lib/elf.c lib/disasm.c lib/cfg.c lib/analyze.c \
            lib/mutate.c lib/exec.c lib/coverage.c lib/corpus.c
LIB_OBJS := $(LIB_SRCS:.c=.o)

CLI_SRCS := src/main.c
CLI_OBJS := $(CLI_SRCS:.c=.o)

TEST_SRCS := $(wildcard tests/test_*.c)
TEST_BINS := $(TEST_SRCS:.c=)

TARGET_SRCS := $(wildcard tests/targets/*.c)
TARGET_BINS := $(TARGET_SRCS:.c=)

INCLUDES := -Iinclude -Ilib

# ── Targets ───────────────────────────────────────────────────────────

.PHONY: all clean test targets install

all: fathom

libfathom.a: $(LIB_OBJS)
	$(AR) rcs $@ $^

fathom: $(CLI_OBJS) libfathom.a
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# ── Compilation rules ────────────────────────────────────────────────

lib/%.o: lib/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

tests/test_%: tests/test_%.c libfathom.a
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< libfathom.a $(LIBS)

# ── Test targets (compiled without protections) ──────────────────────

targets: $(TARGET_BINS)

tests/targets/%: tests/targets/%.c
	$(CC) -O0 -g -fno-stack-protector -no-pie -z execstack -o $@ $<

# ── Test runner ──────────────────────────────────────────────────────

test: $(TEST_BINS)
	@failed=0; \
	for t in $(TEST_BINS); do \
		echo "=== $$t ==="; \
		./$$t || failed=$$((failed + 1)); \
	done; \
	if [ $$failed -ne 0 ]; then \
		echo "$$failed test(s) failed"; exit 1; \
	else \
		echo "All tests passed"; \
	fi

# ── Install ──────────────────────────────────────────────────────────

PREFIX ?= /usr/local

install: fathom libfathom.a
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 fathom $(DESTDIR)$(PREFIX)/bin/
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 644 libfathom.a $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include
	install -m 644 include/fathom.h $(DESTDIR)$(PREFIX)/include/

# ── Clean ────────────────────────────────────────────────────────────

clean:
	rm -f fathom libfathom.a
	rm -f $(LIB_OBJS) $(CLI_OBJS)
	rm -f $(TEST_BINS) $(TARGET_BINS)
