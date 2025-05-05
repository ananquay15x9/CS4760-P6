//Author: Tu Le
//CS4760 Project 6
//Date: 5/5/2025

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include <errno.h>
#include <string.h> 
#include <time.h>

//Define a key for shared memory
#define SHM_KEY_PATH "oss.c" 
#define SHM_KEY_ID 1

//Struct for the simulated clock 
typedef struct {
    unsigned int seconds;
    unsigned int nanoseconds;
} SimulatedClock;

//Global variables for IPC
static int shmid = -1; //Shared memory ID
static SimulatedClock *simClock = NULLL; //Pointer to shared clock

//Function protoypes
static void cleanup(int exit_status);
static void signal_handler(int signum);

int main(int argc, char *argv[]) {
    printf("OSS: Starting...\n");

    //Setup signal handlers for clean termination
    signal(SIGINT, signal_handler); //Handle Ctrl+C
    signal(SIGTERM, signal_handler); //Handle termination signals
    

    //Shared memory setup
    key_t key;

    //1. Generate a unique key for shared memory 
    key = ftok(SHM_KEY_PATH, SHM_KEY_ID);
    if (key == -1) {
	fprintf(stderr, "OSS: Error generating key with ftok: %s\n", sterror(errno));
	exit(EXIT_FAILURE); //Cannot proceed without a key
    }

    //2. Create the shared memory segment
    //IPC_CREAT: Create if it doesn't eist
    //0666: Permissions (read/write for owner, group, others)
    shmid = shmget(key, sizeof(SimulatedClock), IPC_CREAT | 0666);
    if (shmid == -1) {
	fprintf(stderr, "OSS: Error getting shared memory segment with shmget: %s\n", strerror(errno));
	exit(EXIT_FAILURE); //Cannot proceed without shared memory
    }

    //3. Attach the shared memory segment to the process's address space
    simClock = (SimulatedClock *)shmat(shmid, NULL, 0);
    if(simClock == (SimulatedClock *)-1) {
	fprintf(stderr, "OSS: Error attaching shared memory with shmat: %s\n", strerror(errno));
	//
	shmctl(shmid, IPC_RMID, NULL); //Attempt removal
	exit(EXIT_FAILURE);
    }

    //4. Initialize the shared clock
    simClock->seconds = 0;
    simClock->nanoseconds = 0;
    printf("OSS: Shared memory clock initialized at %u:%09u\n", simClock->seconds, simClock->nanoseconds);

    //Main Simulation Loop
    printf("OSS: Entering main loop (placeholder)...\n");
    //we'll increment the clock, fork the children, manage process table, page table, frame table, handle messages from workers, implement LRU page replacement...
    sleep(2); //simple  pause for demonstration

    printf("OSS: Simulation finished (placeholder).\n");

    //Cleanup
    cleanup(EXIT_SUCCESS); //Normal exit

    return 0;
}

//Signal handler function
static void signal_handler(int signum) {
    fprintf(stderr, "\nOSS: Signal %d received. Initiating cleanup...\n", signum);
    //Perform cleanup and exit
    cleanup(EXIT_FAILURE); //Indicate abnormal termination
}

//Cleanup function for IPC resources
static void cleanup(int exit_status) {
    printf("OSS: Cleaning up IPC resources...\n");

    //1. Detach shared memory 
    if (simClock != NULL && simClock != (SimulatedClock *)-1) {
	if (shmdt(simClock) == -1) {
	    fprintf(stderr, "OSS: Warning - Error detaching shared memory: %s\n", strerror(errno));
	    //Continue cleanup even if detach fails
	} else {
	    printf("OSS: Shared memory detached.\n");
	}
	simClock = NULL; //Mark as detached
    }

    //2. Remove shared memory segment (only if we likely created it) 
    //we only remove if shmid is valid. The creator should ideally remove it.
    if (shmid != -1) {
	if (shmctl(shmid, IPC_RMID, NULL) == -1) {
	    //ENOENT or EINVAL might mean it was already removed, which is okay.
	    if (errno != ENOENT && errno != EINVAL) {
		fprintf(stderr, "OSS: Warning - Error removing shared memory (shmid: %d): %s\n", shmid, strerror(errno));
	    }
	} else {
	    printf("OSS: Shared memory segment removed.\n");
	}
	shmid = -1; //Mark as removed/invalid

    }

    printf("OSS: Cleanup finished. Exiting with staus %d.\n", exit_status);
    exit(exit_status);
}






































































