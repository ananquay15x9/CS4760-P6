//Author: Tu Le
//CS4760 Project 6
//Date: 5/5/2025

#ifndef IPC_CONFIG_H
#define IPC_CONFIG_H

#include <sys/types.h>

//Key definitions for IPC resources
#define SHM_KEY_PATH "oss.c"
#define SHM_KEY_ID 1
#define MSG_KEY_ID 2
#define MEMORY_SIZE 32768 //32KB total memory address
#define PAGE_SIZE 1024 //1kb page size
#define NUM_PAGES (MEMORY_SIZE / PAGE_SIZE) //Should be 32

//Structure for the simulated clock
typedef struct {
	unsigned int seconds;
	unsigned int nanoseconds;
} SimulatedClock;

//Message structure for OSS -> Worker
typedef struct {
	long mtype;
	int payload;
} OssMsg;

//Message structure for Worker -> OSS
typedef struct {
	long mtype;
	pid_t sender_pid;
	int memory_address;
	int request_type;
} WorkerMsg;

#define OSS_MSG_TYPE_BASE 1
#define MSG_TYPE_OSS_TO_WORKER 1
#define MSG_TYPE_WORKER_TO_OSS 2
#endif
