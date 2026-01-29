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

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Dependencies
src/fast-completer.o: src/fast-completer.c src/generate_blob.h
src/generate_blob.o: src/generate_blob.c src/generate_blob.h
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
debug: CFLAGS = -g -O0 $(WARNINGS) -DDEBUG
debug: clean all

# Release build (smaller binary)
release: CFLAGS = -O3 $(WARNINGS) -DNDEBUG
release: LDFLAGS = -s
release: clean all
