//Author: Tu Le
//CS4760 Project 6
//Date: 5/5/2025

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include <signal.h>
#include <errno.h>
#include <string.h> 
#include <time.h>
#include "ipc_config.h"

//Global variables for IPC
static int shmid = -1; //Shared memory ID
static int msqid = -1; //Message queue ID
static SimulatedClock *simClock = NULL; //Pointer to shared clock
static pid_t childPid = -1;

//Function protoypes
static void cleanup(int exit_status);
static void signal_handler(int signum);

int main(int argc, char *argv[]) {
    pid_t myPid = getpid(); //Get OSS PID for message queue
    printf("OSS: Starting...\n");

    //Setup signal handlers for clean termination
    signal(SIGINT, signal_handler); //Handle Ctrl+C
    signal(SIGTERM, signal_handler); //Handle termination signals
    

    //Shared memory setup
    key_t shm_key = ftok(SHM_KEY_PATH, SHM_KEY_ID);
    if (shm_key == -1) {
	fprintf(stderr, "OSS: Error ftok (SHM): %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }
    shmid = shmget(shm_key, sizeof(SimulatedClock), IPC_CREAT | 0666);
    if (shmid == -1) {
	fprintf(stderr, "OSS: Error shmget: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }
    simClock = (SimulatedClock *)shmat(shmid, NULL, 0);
    if (simClock == (SimulatedClock *)-1) {
	fprintf(stderr, "OSS: Error shmat: %s\n", strerror(errno));
	shmctl(shmid, IPC_RMID, NULL);
	exit(EXIT_FAILURE);
    }
    simClock->seconds = 0;
    simClock->nanoseconds = 0;
    printf("OSS: Shared memory clock initialized at %u:%09u\n", simClock->seconds, simClock->nanoseconds);


    //Message queue setup
    key_t msg_key = ftok(SHM_KEY_PATH, MSG_KEY_ID); //Use same path, different ID
    if (msg_key == -1) {
	fprintf(stderr, "OSS: Error generating key with ftok: %s\n", strerror(errno));
	cleanup(EXIT_FAILURE); //Cannot proceed without a key
    }
    msqid = msgget(msg_key, IPC_CREAT | 0666);
    if (msqid == -1) {
	fprintf(stderr, "OSS: Error msgget: %s\n", strerror(errno));
	cleanup(EXIT_FAILURE); //Cannot proceed without shared memory
    }
    printf("OSS: Message queue created (ID: %d)\n", msqid);


    //Fork and execute worker here
    printf("OSS: Forking worker process...\n");
    childPid = fork(); //Store the child PID

    if (childPid == -1) {
	fprintf(stderr, "OSS: Error - Failed to fork worker process: %s\n", strerror(errno));
	cleanup(EXIT_FAILURE); //Cleanup before exiting
    } else if (childPid == 0) {
	//Child process
	execl("./worker", "worker", (char *)NULL);
	fprintf(stderr, "OSS (Child): Error exec worker: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    } else {
	//Parent process
	printf("OSS (Parent): Worker process created with PID: %d\n", childPid);

	//Send initial message to worker
	OssMsg oss_message;
	oss_message.mtype = childPid; //Address message to specific worker only
	oss_message.payload = 1;
	printf("OSS (Parent): Sending message (type %ld) to worker %d...\n", oss_message.mtype, childPid);

	//Loop to handle potential EINTR interruptions during msgsnd
	while (msgsnd(msqid, &oss_message, sizeof(OssMsg) - sizeof(long), 0) == -1) {
	    if (errno == EINTR) {
		fprintf(stderr, "OSS (Parent): msgsnd interrupted, retrying...\n");
		continue; //Retry sending
	    } else {
		fprintf(stderr, "OSS (Parent): Error msgsnd to worker %d: %s\n", childPid, strerror(errno));
		//Decide how to handle it, kill or cleanup.
		kill(childPid, SIGTERM); //Terminate child
		cleanup(EXIT_FAILURE);
	    }
	}
	printf("OSS (Parent): Message sent succesfully to worker %d.\n", childPid);
	
	//Wait for message from worker
	WorkerMsg worker_message;
	printf("OSS (Parent): Waiting for message from worker (type %d)...\n", myPid);
	
	//Loop to handle potential EINTR interruptions during msgrcv
	while (msgrcv(msqid, &worker_message, sizeof(WorkerMsg) - sizeof(long), myPid, 0) == -1) {
	    if (errno == EINTR) {
		fprintf(stderr, "OSS (Parent): msgrcv interrupted, retrying...\n");
		continue; //Retry receiving
	    } else {
		fprintf(stderr, "OSS (Parent): Error msgrcv from worker: %s\n", strerror(errno));
		//Decide how to handle, to kill or cleanup.
		kill(childPid, SIGTERM); //Terminate child
		cleanup(EXIT_FAILURE); //Cleanup and exit OSS
	    }
	}

	//Parent process
	printf("OSS (Parent): Received message from worker %d: Address=%d, Type=%s\n",
		(int)worker_message.mtype, //Sender PID is in mtype
		worker_message.memory_address,
		(worker_message.request_type == 0) ? "READ" : "WRITE");

	//Wait for Worker Termination
	printf("OSS (Parent): Waiting for worker process %d to terminate...\n", childPid);
	int status;
	pid_t terminatedPid = waitpid(childPid, &status, 0); //wait specifically for our child

	if (terminatedPid == -1) {
	    fprintf(stderr, "OSS (Parent): Error waiting for child process: %s\n", strerror(errno));
	} else {
	    if (WIFEXITED(status)) {
		printf("OSS (Parent): Worker process %d terminated normally with exit status: %d\n", terminatedPid, WEXITSTATUS(status));
	    } else if (WIFSIGNALED(status)) {
		printf("OSS(Parent): Worker process %d terminated by signal: %d\n", terminatedPid, WTERMSIG(status));
	    } else {
		printf("OSS (Parent): Worker process %d terminated abnormally.\n", terminatedPid);
	    }
	}
	childPid = -1; //Reset childPid as it has terminated
    }

    printf("OSS: Simulation finished.\n");

    //Cleanup
    cleanup(EXIT_SUCCESS); //normal exit

    return 0;
}

//Signal handler function
static void signal_handler(int signum) {
    fprintf(stderr, "\nOSS: Signal %d received. Initiating cleanup...\n", signum);
    if (childPid > 0) {
	printf("OSS: Sending SIGTERM to child process %d\n", childPid);
	if (kill(childPid, SIGTERM) == -1) {
	    perror("OSS: Error sending SIGTERM to child");
    	}
    }
    //Perform cleanup and exit
    cleanup(EXIT_FAILURE); //Indicate abnormal termination
}

//Cleanup function for IPC resources
static void cleanup(int exit_status) {
    printf("OSS: Cleaning up IPC resources...\n");
    
    //Terminate child
    if (childPid > 0) {
	printf("OSS: Checking child %d status during cleanup...\n", childPid);
	int status;
	if (waitpid(childPid, &status, WNOHANG) == 0) {
	    fprintf(stderr, "OSS: Warning - Child %d still running after SIGTERM? Sending SIGKILL.\n", childPid);
	    kill(childPid, SIGKILL);
	    waitpid(childPid, &status, 0); //blocking wait after SIGKILL
	} else {
	   printf("OSS: Child %d confirmed terminated during cleanup.\n", childPid);
	}
	childPid = -1; //Mark child as handled
    }


    //1. Remove message queue
    if (msqid != -1) {
	if (msgctl(msqid, IPC_RMID, NULL) == -1) {
	    if (errno != ENOENT && errno != EINVAL) {
	         fprintf(stderr, "OSS: Warning - msgctl(IPC_RMID) failed: %s\n", strerror(errno));
	    }    
	} else {
	    printf("OSS: Message queue removed.\n");
	}
	msqid = -1;
    }

    //2. Detach shared memory segment 
    if (simClock != NULL && simClock != (SimulatedClock *)-1) {
	if (shmdt(simClock) == -1) {
		fprintf(stderr, "OSS: Warning - shmdt failed: %s\n", strerror(errno));
	} else {
	    printf("OSS: Shared memory segment removed.\n");
	}
	simClock = NULL; //Mark as removed/invalid

    }

    //3. Remove shared memory segment
    if (shmid != -1) {
	if (shmctl(shmid, IPC_RMID, NULL) == -1) {
	    if (errno != ENOENT && errno != EINVAL) {
		fprintf(stderr, "OSS: Warning - shmctl(IPC_RMID) failed: %s\n", strerror(errno));
	    }
	} else {
	    printf("OSS: Shared memory segment removed.\n");
	}
	shmid = -1;
    }

    printf("OSS: Cleanup finished. Exiting with status %d.\n", exit_status);
    exit(exit_status);
}






































































