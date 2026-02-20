# Makefile for fast-completer

CC ?= gcc
WARNINGS = -Wall -Wextra -Wformat=2 -Wshadow -Wunused-result -Wstrict-prototypes \
           -Wnull-dereference -Wduplicated-cond -Wduplicated-branches -Wlogical-op \
           -Wundef -Wwrite-strings
HARDENING = -fstack-protector-strong
CFLAGS ?= -O3 $(WARNINGS) $(HARDENING)
LDFLAGS ?=

# Source files (base)
SRCS = src/fast-completer.c \
       src/diagnostic.c \
       src/generate_blob.c

# Windows needs vendored getopt implementation
ifeq ($(OS),Windows_NT)
    SRCS += src/compat/getopt.c
    TARGET = fast-completer.exe
else
    TARGET = fast-completer
endif

# Object files
OBJS = $(SRCS:.c=.o)

# Install directory (user-local by default)
# Linux/macOS: ~/.local/bin
# Windows: %LOCALAPPDATA%\Programs (via LOCALAPPDATA env var)
ifeq ($(OS),Windows_NT)
    PREFIX ?= $(LOCALAPPDATA)/Programs
    BINDIR ?= $(PREFIX)
else
    PREFIX ?= $(HOME)/.local
    BINDIR ?= $(PREFIX)/bin
endif

ANALYZE_DIR ?= /tmp/scan-build-fast-completer

.PHONY: all clean install uninstall debug release analyze test test-clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Dependencies
src/fast-completer.o: src/fast-completer.c src/generate_blob.h src/diagnostic.h
src/diagnostic.o: src/diagnostic.c src/diagnostic.h
src/generate_blob.o: src/generate_blob.c src/generate_blob.h src/diagnostic.h
ifeq ($(OS),Windows_NT)
src/compat/getopt.o: src/compat/getopt.c src/compat/getopt.h
endif

clean:
	rm -f $(OBJS) $(TARGET)
	rm -rf __pycache__ schemas/*/__pycache__ schemas/*/uv.lock

install: $(TARGET)
	mkdir -p $(BINDIR)
	cp $(TARGET) $(BINDIR)/$(TARGET)

uninstall:
	rm -f $(BINDIR)/$(TARGET)

# Debug build
debug:
	$(MAKE) clean
	$(MAKE) all CFLAGS="-g -O0 $(WARNINGS) $(HARDENING) -DDEBUG -DFCMP_VALIDATE_BLOB"

# Release build (smaller binary)
release:
	$(MAKE) clean
	$(MAKE) all CFLAGS="-O3 $(WARNINGS) $(HARDENING) -DNDEBUG" LDFLAGS="-s"

# Static analysis (clang scan-build)
analyze:
	@command -v scan-build >/dev/null 2>&1 || { \
		echo "scan-build not found. Install clang static analyzer tools."; \
		exit 1; \
	}
	rm -rf $(ANALYZE_DIR)
	mkdir -p $(ANALYZE_DIR)
	scan-build --status-bugs -o $(ANALYZE_DIR) $(MAKE) clean all CC=clang
	@echo "scan-build report: $(ANALYZE_DIR)"

# --- Test targets ---
TEST_DIR = tests
TEST_CFLAGS = -g -O0 $(WARNINGS) $(HARDENING) -DDEBUG -DFCMP_VALIDATE_BLOB

$(TEST_DIR)/test_runtime: $(TEST_DIR)/test_runtime.c src/fast-completer.c \
                          src/generate_blob.c src/generate_blob.h \
                          src/diagnostic.c src/diagnostic.h $(TEST_DIR)/greatest.h
	$(CC) $(TEST_CFLAGS) -Isrc -o $@ \
	    $(TEST_DIR)/test_runtime.c src/diagnostic.c src/generate_blob.c

$(TEST_DIR)/test_generate: $(TEST_DIR)/test_generate.c src/generate_blob.c \
                           src/generate_blob.h src/diagnostic.c src/diagnostic.h \
                           $(TEST_DIR)/greatest.h
	$(CC) $(TEST_CFLAGS) -Isrc -o $@ \
	    $(TEST_DIR)/test_generate.c src/diagnostic.c

ifneq ($(OS),Windows_NT)
$(TEST_DIR)/test_integration: $(TEST_DIR)/test_integration.c $(TEST_DIR)/greatest.h \
                              src/generate_blob.c src/generate_blob.h \
                              src/diagnostic.c src/diagnostic.h $(TARGET)
	$(CC) $(TEST_CFLAGS) -Isrc -o $@ \
	    $(TEST_DIR)/test_integration.c src/diagnostic.c src/generate_blob.c

TEST_BINS = $(TEST_DIR)/test_runtime $(TEST_DIR)/test_generate $(TEST_DIR)/test_integration
else
TEST_BINS = $(TEST_DIR)/test_runtime $(TEST_DIR)/test_generate
endif

test: $(TARGET) $(TEST_BINS)
	@echo "=== test_runtime ===" && $(TEST_DIR)/test_runtime && \
	 echo "=== test_generate ===" && $(TEST_DIR)/test_generate
ifneq ($(OS),Windows_NT)
	@echo "=== test_integration ===" && $(TEST_DIR)/test_integration
endif

test-clean:
	rm -f $(TEST_DIR)/test_runtime $(TEST_DIR)/test_generate $(TEST_DIR)/test_integration
