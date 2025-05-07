//Author: Tu Le
//CS4760 Project 6
//Date: 5/5/2025

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <errno.h>
#include <string.h> 
#include <time.h>
#include "ipc_config.h"

#define MEMORY_SIZE 32768 //32k total memory per process
#define PAGE_SIZE 1024 //1k page size
#define NUM_PAGES (MEMORY_SIZE / PAGE_SIZE) //Should be 32 here
#define MAX_REQUESTS_BEFORE_TERM_CHECK 5 //For testing so 5 is good
#define TERM_PROBABILITY 0.10 //10% chance of terminating after check

// Read/write probability 
#define WRITE_PROBABILITY 0.25 //so 75%


int main (int argc, char *argv[]) {
	pid_t myPid = getpid();
	pid_t parentPid = getppid();

	//Seed random number generator 
	srand(time(NULL) ^ getpid());

	
	printf("WORKER PID:%d PPID:%d: Starting...\n", myPid, parentPid);

	//Shared memory setup
	key_t shm_key = ftok(SHM_KEY_PATH, SHM_KEY_ID);
	int shmid = -1;
	SimulatedClock *simClock = NULL;

	if (shm_key == -1) {
		fprintf(stderr, "WORKER PID:%d: Error generating key with ftok: %s\n", myPid, strerror(errno));
		exit(EXIT_FAILURE);
    	}
	shmid = shmget(shm_key, sizeof(SimulatedClock), 0666);
	if (shmid == -1) {
		fprintf(stderr, "WROKER PID:%d: Error shmget: %s\n", myPid, strerror(errno));
		exit(EXIT_FAILURE);
	}
	simClock = (SimulatedClock *)shmat(shmid, NULL, 0);
	if (simClock == (SimulatedClock *)-1) {
		fprintf(stderr, "WORKER PID:%d: Error shmat: %s\n", myPid, strerror(errno));
		exit(EXIT_FAILURE);
	}
	printf("WORKER PID:%d: Attached to shared memory clock: %u:%09u\n", myPid, simClock->seconds, simClock->nanoseconds);



	//Message queue setup
	key_t msg_key = ftok(SHM_KEY_PATH, MSG_KEY_ID);
	int msqid = -1;

	if (msg_key == -1) {
		fprintf(stderr, "WORKER PID:%d: Error ftok (MSG): %s\n", myPid, strerror(errno));
		shmdt(simClock); //Detach SHM before exit
		exit(EXIT_FAILURE);
	}
	msqid = msgget(msg_key, 0666);
	if (msqid == -1) {
		fprintf(stderr, "WORKER PID:%d: Error msgget: %s\n", myPid, strerror(errno));
		shmdt(simClock); //Detach SHM before exit
		exit(EXIT_FAILURE);
	}
	printf("WORKER PID:%d: Attached to message queue (ID: %d)\n", myPid, msqid);


	//Wait for message from OSS
	OssMsg oss_message;
	printf("WORKER PID:%d: Waiting for message from OSS (type %d)...\n", myPid, myPid);
	//Loop to handle potential EINTR interruptions or queue removal (EIDRM)
	while (msgrcv(msqid, &oss_message, sizeof(OssMsg) - sizeof(long), myPid, 0) == -1) {
		if (errno == EINTR) continue;
		if (errno == EIDRM) {
			fprintf(stderr, "WORKER PID:%d: Message queue removed, exiting\n", myPid);
			shmdt(simClock);
			exit(EXIT_FAILURE);
		} 
		fprintf(stderr, "WORKER PID:%d: Error msgrcv from OSS: %s\n", myPid, strerror(errno));
		shmdt(simClock); //Detach SHM before exit
		exit(EXIT_FAILURE);
	}
	printf("WORKER PID:%d: Received message from OSS. Payload: %d\n", myPid, oss_message.payload);

	//==NEW: Loop for Multiple Requests
	int requests_made = 0;
	int max_requests_this_process = 5 + (rand() % 11);

	for (requests_made = 0; ; requests_made++) {

		//Generate Memory Request
		int memory_address;
		int request_type; //0 for read, 1 for wrte

		//Generate Random Page and Offset
		int random_page = rand() % NUM_PAGES; // 0 to 31
		int random_offset = rand() % PAGE_SIZE; //0 to 1023
		memory_address = (random_page * PAGE_SIZE) + random_offset; // 0 to 32767

		//Determine read or write (biased towards read) 
		double type_rand = (double)rand() / RAND_MAX;
		request_type = (type_rand < WRITE_PROBABILITY) ? 1 : 0; // 1=write, 0=read
	
		//Send Message memory request to OSS
		WorkerMsg worker_message;
		worker_message.mtype = parentPid; //Address message to OSS PID
		worker_message.sender_pid = myPid;
		worker_message.memory_address = memory_address; //Placeholder address
		worker_message.request_type = request_type; //Placeholder type

		printf("WORKER PID:%d: Sending memory request (Addr: %d, Type: %s, Sender: %d) to OSS (type %ld)...\n", 
			myPid, worker_message.memory_address,
			(worker_message.request_type == 0) ? "READ" : "WRITE",
			worker_message.sender_pid,
			worker_message.mtype);

		//Loop to handle potential EINTR interruptions during msgsnd
		while (msgsnd(msqid, &worker_message, sizeof(WorkerMsg) - sizeof(long), 0) == -1) {
			if (errno == EINTR) continue; 
			fprintf(stderr, "WORKER PID:%d: Error msgsnd to OSS: %s\n", myPid, strerror(errno));
			shmdt(simClock); //Detach SHM before exit
			exit(EXIT_FAILURE);
		}
		printf("WORKER PID:%d: Memory request #%d (Addr: %d, Type: %s) sent to OSS.\n", 
			myPid, requests_made + 1, memory_address, (request_type == 0 ? "READ" : "WRITE"));



		//Wait for Confirmation/Grant from OSS
		OssMsg oss_reply;
		printf("WORKER PID:%d: Waiting for grant confirmation from OSS (type %d)...\n", myPid, myPid);

		while (msgrcv(msqid, &oss_reply, sizeof(OssMsg) - sizeof(long), myPid, 0) == -1) {
			if (errno == EINTR) continue;
			if (errno == EIDRM) {
				fprintf(stderr, "WORKER PID:%d: Message queue removed during wait, exiting.\n", myPid);
				shmdt(simClock); 
				exit(EXIT_FAILURE);
			}
			fprintf(stderr, "WORKER_PID:%d: Error msgrcv grant from OSS: %s\n", myPid, strerror(errno));
			shmdt(simClock);
			exit(EXIT_FAILURE);
		}
		printf("WORKER PID:%d: Received grant for request #%d from OSS. Payload: %d\n", 
			myPid, requests_made + 1, oss_reply.payload);	


		//Termation Check == (every 1000 +/- 100 references)
		//For testing only
		if (requests_made > 0 && (requests_made % MAX_REQUESTS_BEFORE_TERM_CHECK == 0)) {
			if ((double)rand() / RAND_MAX < TERM_PROBABILITY || requests_made >= max_requests_this_process) {
				printf("WORKER PID:%d: Deciding to terminate after %d requests.\n", myPid, requests_made + 1);
				break;
			}
		}

	}

    	//Shared memory cleanup
    	printf("WORKER PID:%d: Detaching shared memory...\n", myPid);
    	if (shmdt(simClock) == -1) {
		fprintf(stderr, "WORKER PID:%d: Warning - Error detaching shared memory: %s\n", myPid, strerror(errno));
		//Just exit
    	} else {
		printf("WORKER PID:%d: Shared memory detached.\n", myPid);
    	}

    	printf("WORKER PID:%d PPID:%d: Exiting successfully.\n", myPid, parentPid);
    	exit(EXIT_SUCCESS);
}

