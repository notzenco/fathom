CC      ?= cc
CFLAGS  := -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE \
           $(shell pkg-config --cflags capstone 2>/dev/null)
LDFLAGS :=
LIBS    := $(shell pkg-config --libs capstone 2>/dev/null)

# ── Platform ──────────────────────────────────────────────────────────

UNAME_S := $(shell uname -s)

ifneq (,$(findstring MINGW,$(UNAME_S))$(findstring MSYS,$(UNAME_S)))
  PLATFORM     := windows
  EXE          := .exe
  TARGET_FLAGS := -O0 -g -fno-stack-protector -fno-omit-frame-pointer
else ifeq ($(UNAME_S),Darwin)
  PLATFORM     := macos
  EXE          :=
  TARGET_FLAGS := -O0 -g -fno-stack-protector -fno-omit-frame-pointer
else
  PLATFORM     := linux
  EXE          :=
  TARGET_FLAGS := -O0 -g -fno-stack-protector -fno-omit-frame-pointer \
                  -no-pie -z execstack
endif

# macOS: task_for_pid() needs the debugger entitlement; ad-hoc signing is enough.
ifeq ($(PLATFORM),macos)
  SIGN = codesign --force --sign - --entitlements macos/fathom.entitlements $@
else
  SIGN = @true
endif

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

LIB_SRCS := lib/binary.c lib/fmt_elf.c lib/fmt_macho.c lib/fmt_pe.c \
            lib/disasm.c lib/cfg.c lib/analyze.c lib/mutate.c \
            lib/exec.c lib/exec_posix.c lib/exec_windows.c \
            lib/coverage.c lib/corpus.c lib/osdep.c
LIB_OBJS := $(LIB_SRCS:.c=.o)
LIB_HDRS := include/fathom.h $(wildcard lib/*.h)

CLI_SRCS := src/main.c
CLI_OBJS := $(CLI_SRCS:.c=.o)

TEST_SRCS := $(wildcard tests/test_*.c)
TEST_BINS := $(TEST_SRCS:.c=$(EXE))

TARGET_SRCS := $(wildcard tests/targets/*.c)
TARGET_BINS := $(TARGET_SRCS:.c=$(EXE))

INCLUDES := -Iinclude -Ilib

# ── Targets ───────────────────────────────────────────────────────────

.PHONY: all clean test targets install

all: fathom$(EXE)

libfathom.a: $(LIB_OBJS)
	$(AR) rcs $@ $^

fathom$(EXE): $(CLI_OBJS) libfathom.a
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	$(SIGN)

# ── Compilation rules ────────────────────────────────────────────────

lib/%.o: lib/%.c $(LIB_HDRS)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

src/%.o: src/%.c $(LIB_HDRS)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# Test binaries drive the executor too, so they are signed like fathom.
tests/test_%$(EXE): tests/test_%.c tests/test_util.h libfathom.a
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< libfathom.a $(LIBS)
	$(SIGN)

# ── Test targets (compiled without protections) ──────────────────────

targets: $(TARGET_BINS)

tests/targets/%$(EXE): tests/targets/%.c
	$(CC) $(TARGET_FLAGS) -o $@ $<

# ── Test runner ──────────────────────────────────────────────────────

test: targets $(TEST_BINS)
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

install: fathom$(EXE) libfathom.a
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 fathom$(EXE) $(DESTDIR)$(PREFIX)/bin/
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 644 libfathom.a $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include
	install -m 644 include/fathom.h $(DESTDIR)$(PREFIX)/include/

# ── Clean ────────────────────────────────────────────────────────────

clean:
	rm -f fathom$(EXE) libfathom.a
	rm -f $(LIB_OBJS) $(CLI_OBJS)
	rm -f $(TEST_BINS) $(TARGET_BINS)
