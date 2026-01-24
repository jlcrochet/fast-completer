# Makefile for fast-completer

CC ?= gcc
WARNINGS = -Wall -Wextra -Wformat=2 -Wshadow -Wunused-result -Wstrict-prototypes \
           -Wnull-dereference -Wduplicated-cond -Wduplicated-branches -Wlogical-op \
           -Wundef -Wwrite-strings
HARDENING = -fstack-protector-strong
CFLAGS ?= -O3 $(WARNINGS) $(HARDENING)
LDFLAGS ?=

# Source files (base)
SRCS = fast-completer.c \
       generate_blob.c

# Windows needs vendored getopt implementation
ifeq ($(OS),Windows_NT)
    SRCS += compat/getopt.c
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
fast-completer.o: fast-completer.c generate_blob.h
generate_blob.o: generate_blob.c generate_blob.h
ifeq ($(OS),Windows_NT)
compat/getopt.o: compat/getopt.c compat/getopt.h
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
