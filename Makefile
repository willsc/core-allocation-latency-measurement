CC ?= cc
CFLAGS ?= -O2 -g -fno-omit-frame-pointer -std=c11 -Wall -Wextra -Werror

.PHONY: all test clean
all: build/latprobe

build/latprobe: native/latprobe.c Makefile
	mkdir -p build
	$(CC) $(CFLAGS) $< -o $@ -pthread

test: all
	python3 -m unittest discover -s tests -v

clean:
	rm -rf build
