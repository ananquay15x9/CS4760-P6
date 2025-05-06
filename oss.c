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
#include <stdarg.h>
#include <getopt.h>

#include "ipc_config.h"

//Global variables for IPC
static int shmid = -1; //Shared memory ID
static int msqid = -1; //Message queue ID
static SimulatedClock *simClock = NULL; //Pointer to shared clock
static pid_t childPid = -1;

//Global for step 3
static FILE* log_fp = NULL; //Log file pointer
static char* log_filename = "oss.log"; //Default log file name


//Function protoypes
static void cleanup(int exit_status);
static void signal_handler(int signum);
static void advanceClock(unsigned int seconds, unsigned int nanoseconds);
static void log_message(const char* format, ...);

//Function for Clock Advance
static void advanceClock(unsigned int seconds_inc, unsigned int nano_inc) {
    if (simClock == NULL) return; //Safety check
    
    simClock->nanoseconds += nano_inc;
    simClock->seconds += seconds_inc;

    //Handle nanoseconds rollover
    if (simClock->nanoseconds >= 1000000000) {
	simClock->seconds += simClock->nanoseconds / 1000000000;
	simClock->nanoseconds %= 1000000000;
    }
}

//Function logging for step 3
static void log_message(const char* format, ...) {
    va_list args1, args2;
    va_start(args1, format);
    va_copy(args2, args1);

    //Print timestamp and message to stdout
    printf("OSS [%u:%09u]: ", simClock->seconds, simClock->nanoseconds);
    vprintf(format, args1);
    printf("\n");
    fflush(stdout); //Ensure immediate output to screen
    va_end(args1);

    //Print timestamp and message to log file if open
    if (log_fp != NULL) {
	fprintf(log_fp, "OSS [%u:%09u]: ", simClock->seconds, simClock->nanoseconds);
	vfprintf(log_fp, format, args2);
	fprintf(log_fp, "\n");
	fflush(log_fp); //Ensure immediate output to file
    }
    va_end(args2);
}
int main(int argc, char *argv[]) {
    pid_t myPid = getpid(); //Get OSS PID for message queue

    //Command line parsing for step 3
    int opt;
    //
    while ((opt = getopt(argc, argv, "hf:")) != -1) {
	switch (opt) {
	    case 'f':
		log_filename= optarg;
		break;
	    case 'h':
		printf("Usage: %s [-h] [-f logfile]\n", argv[0]);
		exit(EXIT_SUCCESS);
	    case '?':
		fprintf(stderr, "Unknown option `-%c`.\n", optopt);
		fprintf(stderr, "Usage: %s [-h] [-f logfile]\n", argv[0]);
		exit(EXIT_FAILURE);
	    default:
		fprintf(stderr, "Usage: %s [-h] [-f logfile]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
    }

    //Open log file
    log_fp = fopen(log_filename, "w");
    if (log_fp == NULL) {
	perror("OSS: Error opening log file");
	//Continue without file logging, but print error
	fprintf(stderr, "OSS: Logging to file disabled.\n");
    } else {
	printf("OSS: Logging to file '%s'\n", log_filename);
    }

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
    log_message("Starting..."); //Correctly moved here
    log_message("Shared memory clock initialized at %u:%09u\n", simClock->seconds, simClock->nanoseconds);


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
    log_message("Message queue created (ID: %d)\n", msqid);


    //Fork and execute worker here
    log_message("Forking worker process...\n");
    childPid = fork(); //Store the child PID

    if (childPid == -1) {
	log_message("Error fork: %s", strerror(errno));
	cleanup(EXIT_FAILURE); //Cleanup before exiting
    } else if (childPid == 0) {
	//Child process
	execl("./worker", "worker", (char *)NULL);
	fprintf(stderr, "OSS (Child): Error exec worker: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
    } else {
	//Parent process
	log_message("Worker process created with PID: %d\n", childPid);

	//Send initial message to worker
	OssMsg oss_message;
	oss_message.mtype = childPid; //Address message to specific worker only
	oss_message.payload = 1;
	log_message("Sending message (type %ld) to worker %d...\n", oss_message.mtype, childPid);

	//Loop to handle potential EINTR interruptions during msgsnd
	while (msgsnd(msqid, &oss_message, sizeof(OssMsg) - sizeof(long), 0) == -1) {
	    if (errno == EINTR) {
		fprintf(stderr, "OSS (Parent): msgsnd interrupted, retrying...\n");
		continue; //Retry sending
	    } else {
		log_message("Error msgsnd to worker %d: %s", childPid, strerror(errno));
		//Decide how to handle it, kill or cleanup.
		kill(childPid, SIGTERM); //Terminate child
		cleanup(EXIT_FAILURE);
	    }
	}
	log_message("Initial Message sent succesfully to worker %d.", childPid);
	
	//Wait for message from worker
	WorkerMsg worker_message;
	log_message("Waiting for message from worker (type %d)...\n", myPid);
	
	//Loop to handle potential EINTR interruptions during msgrcv
	while (msgrcv(msqid, &worker_message, sizeof(WorkerMsg) - sizeof(long), myPid, 0) == -1) {
	    if (errno == EINTR) {
		log_message("msgrcv from worker interrupted, retrying...\n");
		continue; //Retry receiving
	    } else {
		log_message("Error msgrcv from worker: %s", strerror(errno));
		//Decide how to handle, to kill or cleanup.
		kill(childPid, SIGTERM); //Terminate child
		cleanup(EXIT_FAILURE); //Cleanup and exit OSS
	    }
	}

	//Handler for Step 3
	pid_t workerPid = worker_message.sender_pid; //Get sender PID from message
	int address = worker_message.memory_address;
	int type = worker_message.request_type;

	//1. Log request
	log_message("P%d requesting %s of address %d", workerPid, (type == 0) ? "read" : "write", address);

	//2. Advance Clock
	advanceClock(0, 100);

	//3. Log Grant
	log_message("Granting P%d %s request for address %d", workerPid, (type == 0) ? "read" : "write", address);

	//4. Send confirmation/grant back to worker
	OssMsg grant_message;
	grant_message.mtype = workerPid; //Send to specific worker
	grant_message.payload = 1;
	log_message("Sending grant confirmation to P%d (type %ld)...", workerPid, grant_message.mtype);

	while (msgsnd(msqid, &grant_message, sizeof(OssMsg) - sizeof(long), 0) == -1) {
	    if (errno == EINTR) {
		log_message("msgsnd grant interrupted, retrying...");
		continue;
	    } else {
		log_message("Error msgsnd grant to P%d: %s", workerPid, strerror(errno));
		kill(workerPid, SIGTERM);
		cleanup(EXIT_FAILURE);
	    }
	}
	log_message("Grant confirmation sent to P%d.", workerPid);


	//Wait for Worker Termination
	log_message("Waiting for worker process P%d to terminate...\n", workerPid);
	int status;
	pid_t terminatedPid = waitpid(workerPid, &status, 0); //wait specifically for our child

	if (terminatedPid == -1) {
	    log_message("Error waiting for child process P%d: %s", workerPid, strerror(errno));
	} else {
	    if (WIFEXITED(status)) {
		log_message("Worker P%d terminated normally (status: %d)", terminatedPid, WEXITSTATUS(status));
	    } else if (WIFSIGNALED(status)) {
		log_message("Worker P%d terminated by signal: %d", terminatedPid, WTERMSIG(status));
	    } else {
		log_message("Worker P%d terminated abnormally.\n", terminatedPid);
	    }
	}
	childPid = -1; //Reset childPid as it has terminated
    }

    log_message("Simulation finished.\n");

    //Cleanup
    cleanup(EXIT_SUCCESS); //normal exit
    return 0;
}

//Signal handler function
static void signal_handler(int signum) {
    fprintf(stderr, "\nOSS: Signal %d received. Initiating cleanup...\n", signum);
    if(log_fp) fprintf(log_fp, "\nOSS: Signal %d received. Initiating cleanup...\n", signum);

    if (childPid > 0) {
	fprintf(stderr, "OSS: Sending SIGTERM to child process %d\n", childPid);
	if(log_fp) fprintf(log_fp, "OSS: Sending SIGTERM to child process %d\n", childPid);
	if (kill(childPid, SIGTERM) == -1) {
	    perror("OSS: Error sending SIGTERM to child");
	    if(log_fp) fprintf(log_fp, "OSS: Error sending SIGTERM to child: %s\n", strerror(errno));
    	}
    }
    //Perform cleanup and exit
    cleanup(EXIT_FAILURE); //Indicate abnormal termination
}

//Cleanup function for IPC resources
static void cleanup(int exit_status) {
    printf("OSS: Cleaning up IPC resources...\n");
    if(log_fp) fprintf(log_fp, "OSS: Cleaning up IPC resources...\n");

    
    //Terminate child
    if (childPid > 0) {
	printf("OSS: Checking child %d status during cleanup...\n", childPid);
	if(log_fp) fprintf(log_fp, "OSS: Checking child %d status during cleanup...\n", childPid);
	int status;
	if (waitpid(childPid, &status, WNOHANG) == 0) {
	    fprintf(stderr, "OSS: Warning - Child %d still running after SIGTERM? Sending SIGKILL.\n", childPid);
	    if(log_fp) fprintf(log_fp, "OSS: Warning - Child %d still running after SIGTERM? Sending SIGKILL.\n", childPid);
	    kill(childPid, SIGKILL);
	    waitpid(childPid, &status, 0); //blocking wait after SIGKILL
	} else {
	    printf("OSS: Child %d confirmed terminated during cleanup.\n", childPid);
	    if(log_fp) fprintf(log_fp, "OSS: Child %d confirmed terminated during cleanup.\n", childPid);
	}
	childPid = -1; //Mark child as handled
    }


    //1. Remove message queue
    if (msqid != -1) {
	if (msgctl(msqid, IPC_RMID, NULL) == -1) {
	    if (errno != ENOENT && errno != EINVAL) {
		fprintf(stderr, "OSS: Warning - msgctl(IPC_RMID) failed: %s\n", strerror(errno));
		if(log_fp) fprintf(log_fp, "OSS: Warning -msgctl(IPC_RMID) failed: %s\n", strerror(errno));
	    }    
	} else {
	    printf("OSS: Message queue removed.\n");
	    if(log_fp) fprintf(log_fp, "OSS: Message queue removed.\n");
	}
	msqid = -1;
    }

    //2. Detach shared memory segment 
    if (simClock != NULL && simClock != (SimulatedClock *)-1) {
	if (shmdt(simClock) == -1) {
		fprintf(stderr, "OSS: Warning - shmdt failed: %s\n", strerror(errno));
		if(log_fp) fprintf(log_fp, "OSS: Warning - shmdt failed: %s\n", strerror(errno));
	} else {
	    printf("OSS: Shared memory segment detached.\n");
	    if(log_fp) fprintf(log_fp, "OSS: Shared memory detached.\n");
	}
	simClock = NULL; //Mark as removed/invalid

    }

    //3. Remove shared memory segment
    if (shmid != -1) {
	if (shmctl(shmid, IPC_RMID, NULL) == -1) {
	    if (errno != ENOENT && errno != EINVAL) {
		fprintf(stderr, "OSS: Warning - shmctl(IPC_RMID) failed: %s\n", strerror(errno));
		if(log_fp) fprintf(log_fp, "OSS: Warning - shmctl(IPC_RMID) failed: %s\n", strerror(errno));
	    }
	} else {
	    printf("OSS: Shared memory segment removed.\n");
	    if(log_fp) fprintf(log_fp, "OSS: Shared memory segment removed.\n");
	}
	shmid = -1;
    }

    //Close log file
    if (log_fp != NULL) {
	printf("OSS: Closing log file.\n"); 
	fprintf(log_fp, "OSS: Cleanup finished. Exiting with status %d.\n", exit_status);
	fclose(log_fp);
	log_fp = NULL;
    }

    printf("OSS: Cleanup finished. Exiting with status %d.\n", exit_status);
    exit(exit_status);
}






































































