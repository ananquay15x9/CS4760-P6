#Author: Tu Le
#CS4760 Project 6
#Date: 5/5/2025

CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lrt

#Target executables
OSS_TARGET = oss
WORKER_TARGET = worker

#Object files
OSS_OBJS = oss.o
WORKER_OBJS = worker.o

all: $(OSS_TARGET) $(WORKER_TARGET)

$(OSS_TARGET): $(OSS_OBJS)
    $(CC) $(CFLAGS) -o $(OSS_TARGET) $(OSS_OBJS) $(LDFLAGS)

$(WORKER_TARGET): $(WORKER_OBJS)
    $(CC) $(CFLAGS) -o $(WORKER_TARGET) $(WORKER_OBJS) $(LDFLAGS)

oss.o: oss.c
    $(CC) $(CFLAGS) -c oss.c

worker.o: worker.c
    $(CC) $(CFLAGS) -c worker.c

clean:
    rm -f $(OSS_TARGET) $(WORKER_TARGET) *.o *.log core.*

.PHONY: clean all
