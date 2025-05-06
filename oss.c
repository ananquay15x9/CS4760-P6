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
#include <ctype.h>

#include "ipc_config.h"

//Step 4 Define
#define MAX_CONCURRENT_PROCS 18 //Max controlled by -s
#define HARD_PROC_LIMIT 18 //Cannot exceed this many concurrent processes
#define DEFAULT_TOTAL_PROCS 5 //Default for -n
#define DEFAULT_MAX_CONCURRENT 5 //Default for -s
#define DEFAULT_LAUNCH_INTERVAL_MS 500 //Default for -i (ms)

//Step 4 PCB Structure Start
typedef struct {
    pid_t pid; 
    int occupied; // 0 = free, 1 = occupied
    unsigned int start_seconds; //Time when created (from simClock)
    unsigned int start_nanos; //Time when created (from simClock)
} ProcessControlBlock;

//Global variables for IPC
static int shmid = -1; //Shared memory ID
static int msqid = -1; //Message queue ID
static SimulatedClock *simClock = NULL; //Pointer to shared clock


//Global for step 3
static FILE* log_fp = NULL; //Log file pointer
static char* log_filename = "oss.log"; //Default log file name

//Step 4 Globals
static ProcessControlBlock pcbTable[HARD_PROC_LIMIT]; //Holds all PCBs
static int max_total_children = DEFAULT_TOTAL_PROCS; //Max total children to launch -n
static int max_concurrent_children = DEFAULT_MAX_CONCURRENT; //Max concurrent children -s
static int launch_interval_ns = DEFAULT_LAUNCH_INTERVAL_MS * 1000000; //Interval -i
static int active_children_count = 0;   // Current number of running children
static int total_children_launched = 0; // Total children launched so far
static unsigned int next_launch_time_s = 0; // Clock time for next launch
static unsigned int next_launch_time_ns = 0; // Clock time for next launch
static volatile sig_atomic_t terminate_flag = 0; 

//Function protoypes
static void cleanup(int exit_status);
static void signal_handler(int signum);
static void advanceClock(unsigned int seconds, unsigned int nanoseconds);
static void log_message(const char* format, ...);
static int findFreePcbSlot();
static void initializePcbTable();


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

//Step 4 Function Initialize PCB Table
static void initializePcbTable() {
    for (int i = 0; i < HARD_PROC_LIMIT; i++) {
	pcbTable[i].occupied = 0;
	pcbTable[i].pid = 0;
	pcbTable[i].start_seconds = 0;
	pcbTable[i].start_nanos = 0;
    }
    log_message("PCB table initialized.");
}

//Step 4 Find free PCB Slot
static int findFreePcbSlot() {
    for (int i = 0; i < HARD_PROC_LIMIT; i++) {
	if (!pcbTable[i].occupied) {
	    return i; //Return index of free slot
	}
    }
    return -1; //No free slot found
}


//====MAIN=====
int main(int argc, char *argv[]) {
    pid_t myPid = getpid(); //Get OSS PID for message queue 

    //Command line parsing for step 3
    int opt;
    int interval_ms = DEFAULT_LAUNCH_INTERVAL_MS;
    //
    while ((opt = getopt(argc, argv, "hn:s:i:f:")) != -1) {
	switch (opt) {
	    case 'n': //Max total processes to launch
		max_total_children = atoi(optarg);
		if (max_total_children <= 0) {
		    fprintf(stderr, "OSS: Error: -n value must be positive.\n");
		    exit(EXIT_FAILURE);
		}
		break;
	    case 's': //Max concurrent processes
		max_concurrent_children = atoi(optarg);
		if (max_concurrent_children <= 0) {
		    fprintf(stderr, "OSS: Error: -s value must be positive.\n");
		    exit(EXIT_FAILURE);
		}
		if (max_concurrent_children > HARD_PROC_LIMIT) {
		    fprintf(stderr, "OSS: Warning: -s value %d exceeds hard limit %d. Using %d.\n", 
			    max_concurrent_children, HARD_PROC_LIMIT, HARD_PROC_LIMIT);
		    max_concurrent_children = HARD_PROC_LIMIT;
		}
		break;
	    case 'i': //Interval between launches in ms
		interval_ms = atoi(optarg);
		if (interval_ms <= 0) {
		    fprintf(stderr, "OSS: Error: -i value must be positive.\n");
		    exit(EXIT_FAILURE);
		}
		launch_interval_ns = interval_ms * 1000000; //Convert ms to ns
		break;
	    case 'f':
		log_filename= optarg;
		break;
	    case 'h':
		printf("Usage: %s [-h] [-n proc] [-s simul] [-i intervalInMs] [-f logfile]\n", argv[0]);
		printf("    -n proc: Max total number of child processes to launch (default: %d).\n", DEFAULT_TOTAL_PROCS);
		printf("    -s simul: Max number of concurrent child processes (default: %d, max: %d).\n", DEFAULT_MAX_CONCURRENT, HARD_PROC_LIMIT);
		printf("    -i intervalInMs: Milliseconds between child launches (default: %dms).\n", DEFAULT_LAUNCH_INTERVAL_MS);
		printf("    -f logfile: Name of the log file (default: %s).\n", log_filename);
		exit(EXIT_SUCCESS);
	    case '?':
		if (optopt == 'n' || optopt == 's' || optopt == 'i' || optopt == 'f')
		    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
		else if (isprint(optopt))
		    fprintf(stderr, "Unknown option `-%c`.\n", optopt);
		else
		    fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
		exit(EXIT_FAILURE);
	    default:
		fprintf(stderr, "Usage: %s [-h] [-n proc] [-s simul] [-i intervalInMs] [-f logfile]\n", argv[0]);
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
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler; 
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    //Set 5 seconds 
    alarm(5);
    sigaction(SIGALRM, &sa, NULL); //Handle SIGALRM
    

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

    //Initialize PCB table
    initializePcbTable(); 

    //Log startup messages
    log_message("Starting... (PID: %d)", myPid); //Correctly moved here
    log_message("Parameters: MaxTotal=%d, MaxConcurrent=%d, LaunchInterval=%dns, LogFile='%s'",
		max_total_children, max_concurrent_children, launch_interval_ns, log_filename);
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


    //Step 4 Main Simulation Loop Start
    log_message("Starting main simulation loop...");
    //Calculate initial launch time
    next_launch_time_s = simClock->seconds;
    next_launch_time_ns = simClock->nanoseconds + (rand() % launch_interval_ns);
    if (next_launch_time_ns >= 1000000000) {
	next_launch_time_s++;
	next_launch_time_ns -= 1000000000;
    }

    while (!terminate_flag) {
	//Check termination conditions
	if (total_children_launched >= max_total_children && active_children_count == 0) {
	    log_message("All %d children launched and terminated. Ending simulation.", max_total_children);
	    terminate_flag = 1; //Signal loop to end
	    break;
	}

	//Advance Clock
	advanceClock(0, 100000); //e.g., 100ms per loop

	//Check for terminated children
	int status;
	pid_t terminatedPid;
	//Use while loop to reap all zombies that might exists
	while ((terminatedPid = waitpid(-1, &status, WNOHANG)) > 0) {
	    log_message("Child P%d terminated.", terminatedPid);
	    int pcbIndex = -1;
	    for (int i = 0; i < HARD_PROC_LIMIT; i++) {
		if (pcbTable[i].occupied && pcbTable[i].pid == terminatedPid) {
		    pcbIndex = i;
		    break;
		}
	    }
	    if (pcbIndex != -1) {
		log_message("Clearing PCB entry %d for P%d", pcbIndex, terminatedPid);
		pcbTable[pcbIndex].occupied = 0;
		pcbTable[pcbIndex].pid = 0;
		active_children_count--;

		if (WIFEXITED(status)) { 
		    log_message("P%d terminated normally (status: %d)", terminatedPid, WEXITSTATUS(status)); 
		} else if (WIFSIGNALED(status)) { 
		    log_message(" P%d terminated by signal: %d", terminatedPid, WTERMSIG(status)); 
		} else { 
		    log_message(" P%d terminated abnormally.", terminatedPid); 
		} 
	    } else {
		log_message("Error: Could not find PCB entry for terminated child P%d", terminatedPid);
	    }
	}
	//ignore ECHILD
	if (terminatedPid == -1 && errno != ECHILD) {
	    log_message("Error: waitpid failed: %s", strerror(errno));
	    terminate_flag = 1; //end simul on unexpected error
	}

	//Launch new children
	if (total_children_launched < max_total_children &&
	    active_children_count < max_concurrent_children &&
	    (simClock->seconds > next_launch_time_s ||
	    (simClock->seconds == next_launch_time_s && simClock->nanoseconds >= next_launch_time_ns)))
	{
	    int pcbIndex = findFreePcbSlot();
	    if (pcbIndex != -1) {
		log_message("Attempting to launch child #%d (concurrent: %d) into PCB %d",
			    total_children_launched + 1, active_children_count + 1, pcbIndex);


		pid_t tempPid = fork();
		if (tempPid == -1) {
		    log_message("Error: fork failed for child #%d: %s", total_children_launched + 1, strerror(errno));
		} else if (tempPid == 0) {
		    //Child process
		    execl("./worker", "worker", (char *)NULL);
		    fprintf(stderr, "OSS (Child #%d): Error exec worker: %s\n", total_children_launched + 1, strerror(errno));
		    exit(EXIT_FAILURE);
		} else {
		    //Parent process: Update PCB and counters
		    pcbTable[pcbIndex].pid = tempPid;
		    pcbTable[pcbIndex].occupied = 1;
		    pcbTable[pcbIndex].start_seconds = simClock->seconds;
		    pcbTable[pcbIndex].start_nanos = simClock->nanoseconds;
		    active_children_count++;
		    total_children_launched++;
		    log_message("Launched child P%d (PID %d) into PCB %d. Total launched: %d, Active: %d",
				pcbIndex, tempPid, pcbIndex, total_children_launched, active_children_count);

		    //Send initial message to worker
		    OssMsg oss_message;
		    oss_message.mtype = pcbTable[pcbIndex].pid; 
		    oss_message.payload = 1;
		    while (msgsnd(msqid, &oss_message, sizeof(OssMsg) - sizeof(long), 0) == -1) {
			if (errno == EINTR) continue;
			log_message("Error: msgsnd initial failed for P%d: %s", pcbIndex, strerror(errno));
			//we'll kill the child if initial message fails
			kill(pcbTable[pcbIndex].pid, SIGTERM);
			pcbTable[pcbIndex].occupied = 0; 
			active_children_count--;
			total_children_launched--; //Decrement launched count
			break;
		    }

		    //Calculate next launch time
		    next_launch_time_s = simClock->seconds;
		    //Add random variation around the interval: interval +/- 50%
		    int random_offset_ns = (rand() % (launch_interval_ns)) - (launch_interval_ns / 2);
		    next_launch_time_ns = simClock->nanoseconds + launch_interval_ns + random_offset_ns;
		    if (next_launch_time_ns < simClock->nanoseconds) next_launch_time_ns = simClock->nanoseconds;

		    while (next_launch_time_ns >= 1000000000) {
			next_launch_time_s++;
			next_launch_time_ns -= 1000000000;
		    }
		    log_message("Next launch scheduled around %u:%09u", next_launch_time_s, next_launch_time_ns);
		}
	    } else {
		log_message("Warning: Conditions met to launch child, but no free PCB slots available (Active: %d).", active_children_count);
		next_launch_time_s = simClock->seconds;
		next_launch_time_ns = simClock->nanoseconds + 1000000;
		if (next_launch_time_ns >= 1000000000) { /* handle rollover */}
	    }
	}

	//Check incoming messages
	//Wait for message from worker
	WorkerMsg worker_message;

	//Loop to handle potential EINTR interruptions during msgrcv
	while (msgrcv(msqid, &worker_message, sizeof(WorkerMsg) - sizeof(long), myPid, IPC_NOWAIT) != -1) {
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
	    while (msgsnd(msqid, &grant_message, sizeof(OssMsg) - sizeof(long), 0) == -1) {
	        if (errno == EINTR) continue; 
		log_message("Error msgsnd grant to P%d: %s", workerPid, strerror(errno));
		break;
	    } 
	    if (errno != EINTR) log_message("Grant confirmation sent to P%d.", workerPid); // Log if not interrupted
	    advanceClock(0, 1000);

	}
	//Check errno
	if (errno != ENOMSG && errno != EINTR) {
	    log_message("Error: msgrcv failed in main loop: %s", strerror(errno));
	    terminate_flag = 1;
	}
    }


    log_message("Simulation loop finished. Cleaning up...");
    //Cleanup
    cleanup(EXIT_SUCCESS); //normal exit
    return 0;
}

//Signal handler function
static void signal_handler(int signum) {
    fprintf(stderr, "\nOSS: Signal %d received. Initiating cleanup...\n", signum);
    if(log_fp) fprintf(log_fp, "\nOSS: Signal %d received. Initiating cleanup...\n", signum);
    terminate_flag = 1;
}


//Cleanup function for IPC resources
static void cleanup(int exit_status) {
    printf("OSS: Cleaning up IPC resources...\n");
    if(log_fp) fprintf(log_fp, "OSS: Cleaning up IPC resources...\n");

    
    //Make sure children are terminated if loop exited
    int children_signaled = 0;
    for (int i = 0; i < HARD_PROC_LIMIT; i++) {
	if (pcbTable[i].occupied) {
	    children_signaled++;
	    printf("OSS: Cleanup: Sending SIGTERM to active child P%d (PID %d)\n", i, pcbTable[i].pid);
	    if (log_fp) fprintf(log_fp, "OSS: Cleanup: Sending SIGTERM to active child P%d (PID %d)\n", i, pcbTable[i].pid);
	    kill(pcbTable[i].pid, SIGTERM); // Send SIGTERM first
	}
    }

    //Brief sleep to allow children to handle SIGTERM 
    if (children_signaled > 0) sleep(1);

    //Force kill any that didn't terminate and wait for them
    int children_killed = 0;
    int status;
    for (int i = 0; i < HARD_PROC_LIMIT; i++) {
	if (pcbTable[i].occupied) {
	    // Check if it terminated already (non-blocking)
	    if (waitpid(pcbTable[i].pid, &status, WNOHANG) == 0) {
		// Still running, send SIGKILL
                children_killed++;
		printf("OSS: Cleanup: Child P%d (PID %d) unresponsive, sending SIGKILL.\n", i, pcbTable[i].pid);
                if (log_fp) fprintf(log_fp, "OSS: Cleanup: Child P%d (PID %d) unresponsive, sending SIGKILL.\n", i, pcbTable[i].pid);
                kill(pcbTable[i].pid, SIGKILL);
                waitpid(pcbTable[i].pid, &status, 0); // Blocking wait after SIGKILL
                printf("OSS: Cleanup: Child P%d (PID %d) reaped after SIGKILL.\n", i, pcbTable[i].pid);
                if (log_fp) fprintf(log_fp, "OSS: Cleanup: Child P%d (PID %d) reaped after SIGKILL.\n", i, pcbTable[i].pid);
	    } else {
		//Child termianted
		printf("OSS: Cleanup: Child P%d (PID %d) already terminated.\n", i, pcbTable[i].pid);
		if (log_fp) fprintf(log_fp, "OSS: Cleanup: Child P%d (PID %d) already terminated.\n", i, pcbTable[i].pid);
	    }
	    pcbTable[i].occupied = 0; //PCB now free
	}
    }
    active_children_count = 0;		

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






































































