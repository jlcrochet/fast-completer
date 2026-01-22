# Makefile for fast-completer

CC ?= gcc
CFLAGS ?= -O3 -Wall -Wextra
LDFLAGS ?=

# Include paths for vendor libraries
INCLUDES = -Ivendor/libyaml/include -DHAVE_CONFIG_H

# Source files
SRCS = fast-completer.c \
       generate_blob.c \
       vendor/cjson/cJSON.c \
       vendor/libyaml/src/api.c \
       vendor/libyaml/src/reader.c \
       vendor/libyaml/src/scanner.c \
       vendor/libyaml/src/parser.c \
       vendor/libyaml/src/loader.c

# Object files
OBJS = $(SRCS:.c=.o)

# Output binary
ifeq ($(OS),Windows_NT)
    TARGET = fast-completer.exe
else
    TARGET = fast-completer
endif

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
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# Dependencies
fast-completer.o: fast-completer.c generate_blob.h
generate_blob.o: generate_blob.c generate_blob.h vendor/cjson/cJSON.h vendor/libyaml/include/yaml.h

clean:
	rm -f $(OBJS) $(TARGET)
	rm -rf __pycache__ schemas/*/__pycache__

install: $(TARGET)
	mkdir -p $(BINDIR)
	cp $(TARGET) $(BINDIR)/$(TARGET)

uninstall:
	rm -f $(BINDIR)/$(TARGET)

# Debug build
debug: CFLAGS = -g -O0 -Wall -Wextra -DDEBUG
debug: clean all

# Release build (smaller binary)
release: CFLAGS = -O3 -Wall -Wextra -DNDEBUG
release: LDFLAGS = -s
release: clean all
