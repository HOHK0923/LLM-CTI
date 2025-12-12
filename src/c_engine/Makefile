CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
TARGET = log_parser
OBJS = main.o log_parser.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

main.o: main.c log_parser.h
	$(CC) $(CFLAGS) -c main.c

log_parser.o: log_parser.c log_parser.h
	$(CC) $(CFLAGS) -c log_parser.c

clean:
	rm -f $(OBJS) $(TARGET)

install:
	cp $(TARGET) ../../bin/

.PHONY: all clean install
