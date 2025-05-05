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
#include "ipc_config.h"


int main (int argc, char *argv[]) {
	pid_t myPid = getpid();
	pid_t parentPid = getppid();

	printf("WORKER PID:%d PPID:%d: Starting...\n", myPid, parentPid);

	//Shared memory setup
	key_t shm_key = ftok(SHM_KEY_PATH, SHM_KEY_ID);
	int shmid = -1;
	SimulatedClock *simClock = NULL;

	if (shm_key == -1) {
		fprintf(stderr, "WORKER PID:%d: Error generating key with ftok: %s\n", myPid, strerror(errno));
		exit(EXIT_FAILURE);
    	}

	//2. Get the existing shared memory segment ID
	shmid = shmget(shm_key, sizeof(SimulatedClock), 0666);
	if (shmid == -1) {
		fprintf(stderr, "WORKER PID:%d: Error shmget: %s\n", myPid, strerror(errno));
		exit(EXIT_FAILURE);
    	}

	//3. Attach the shared memory segment
	simClock = (SimulatedClock *)shmat(shmid, NULL, 0);
	if (simClock == (SimulatedClock *)-1) {
		fprintf(stderr, "WORKER PID:%d: Error attaching shared memory with shmat: %s\n", myPid, strerror(errno));
		exit(EXIT_FAILURE);
	}

	//Access Shared Clock
    	printf("WORKER PID:%d PPID:%d: Attached to shared memory clock: %u:%09u\n", 
		myPid, parentPid, simClock->seconds, simClock->nanoseconds);

	//Message queue setup
	key_t msg_key = ftok(MSG_KEY_PATH, MSG_KEY_ID);
	int msqid = -1;

	if (msg_key == -1) {
		fprintf(stderr, "WORKER PID:%d: Error ftok (MSG): %s\n", myPid, strerror(errno));
		shmdt(simClock); //Detach SHM before exit
		exit(EXIT_FAILURE);
	}

	//Get the existing message queue ID
	msqid = msgget(msg_key, 0666);
	if (msqid == -1) {
		fprintf(stderr, "WORKER PID:%d: Error msgget: %s\n", myPid, strerror(errno));
		fprintf(stderr, "WORKER PID:%d: (Did OSS create the message queue?)\n", myPid);
		shmdt(simClock); //Detach SHM before exit
		exit(EXIT_FAILURE);
	}
	printf("WORKER PID:%d: Attached to message queue (ID: %d)\n", myPid, msqid);

	//Wait for message from OSS
	OssMsg oss_message;
	printf("WORKER PID:%d: Waiting for message from OSS (type %d)...\n", myPid, myPid);

	//Loop to handle potential EINTR interruptions or queue removal (EIDRM)
	while (msgrcv(msqid, &oss_message, sizeof(OssMsg) - sizeof(long), myPid, 0) == -1) {
		if (errno == EINTR) {
			fprintf(stderr, "WORKER PID:%d: msgrcv interrupted, retrying...\n", myPid);
			continue;
		} else if (errno == EIDRM) {
			fprintf(stderr, "WORKER PID:%d: Message queue removed, exiting.\n", myPid);
			shmdt(simClock);
			exit(EXIT_FAILURE);
		} else {
			fprintf(stderr, "WORKER PID:%d: Error msgrcv from OSS: %s\n", myPid, strerror(errno));
			shmdt(simClock); //Detach SHM before exit
			exit(EXIT_FAILURE);
		}
	}
	printf("WORKER PID:%d: Received message from OSS. Payload: %d\n", myPid, oss_message.payload);

	//Send Message memory request to OSS
	WorkerMsg worker_message;
	worker_message.mtype = parentPid; //Address message to OSS PID
	worker_message.memory_address = 1024; //Placeholder address
	worker_message.request_type = 0; //Placeholder type

	printf("WORKER PID:%d: Sending memory request (Addr: %d, Type: %d) to OSS (type %ld)...\n", 
		myPid, worker_message.memory_address, worker_message.request_type, worker_message.mtype);

	//Loop to handle potential EINTR interruptions during msgsnd
	while (msgsnd(msqid, &worker_message, sizeof(WorkerMsg) - sizeof(long), 0) == -1) {
		if (errno == EINTR) {
			fprintf(stderr, "WORKER PID:%d: msgsnd interrupted, retrying...\n", myPid);
			continue; //Retry sending
		} else {
			fprintf(stderr, "WORKER PID:%d: Error msgsnd to OSS: %s\n", myPid, strerror(errno));
			//No need to exit immediately, but try to cleanup first
			shmdt(simClock); //Detach SHM before exit
			exit(EXIT_FAILURE);
		}
	}
	printf("WORKER PID:%d: Memory request sent to OSS.\n", myPid);

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
