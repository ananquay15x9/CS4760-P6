# CS4760 - Project 6: Page Replacement and Memory Management
**Git Repository:** [https://github.com/ananquay15x9/CS4760-P6](https://github.com/ananquay15x9/CS4760-P6.git)

## Project Description

This project implements a memory management and page replacement module for an Operating System Simulator (oss). The system simulates concurrent worker processes making memory access
requests (reads and writes) while the master (oss) manages page tables, frame allocation, and page replacement using the Least Recently Used (LRU) algorithm. Key features include:

* Per-process page tables and a global frame table
* LRU page replacement with simulated dirty bit and I/O delays
* Non-blocking interprocess communication (IPC) using message queues
* Shared memory clock simulation
* Periodic memory layout and statistics output

## Compilation

To compile this project, navigate to the project directory and run 'make' in the terminal:

```bash
make
```

## Running

To run the project, execute ./oss with the following command-line options:

* '-h': Display help information
* '-n <num_processes>': Specify the number of total processes to launch (maximum concurrent: 18)
* '-s <max_concurrent>': Maximum number of concurrent user processes
* '-i <interval_in_ms>': Interval in milliseconds between child process launches
* '-f <logfile>': Specify the log file name 

Example:
```bash
./oss -n 40 -s 5 -i 500 -f oss.log 
```

## Implementation Details

1. **Memory Management**:
   - System memory: 128KB, divided into 256 frames (1KB each)
   - Per-process memory: 32KB, divided into 32 pages (1KB each)
   - Frame Table: Tracks which process/page occupies each frame, dirty bit, and last reference time (for LRU)
   - Page Table: Each proecss has a 32-entry page table mapping its pages to frames

2. **Page Replacement**:
   - LRU Algorithm: On page fault, the frame with the oldest last reference timestamp is selected for replacement
   - Dirty Bit: Set on write; if a dirty page is evicted, an extra I/O delay is simulated
   - I/O Simulation: Page faults incur a 14ms simulated I/O delay; dirty evictions add another 14ms

3. **Worker Process Behavior**:
   - Each worker generates random memory requests (biased toward reads)
   - Requests are sent to oss via message queue and block until granted
   - Workers randomly decide to terminate after a number of requests

4. **Logging and Output**:
   - All oss output is logged to both the screen and a specified logfile
   - The memory layout (frame table and page tables) is printed every simulated second
   - Statistics are printed at the end:
     - Total memory accesses
     - Total page faults
     - Memory accesses per simulated second
     - Page faults per memory access


## Problems Encountered and Solutions

1. **LRU Implementation Bug**:
   - **Problem**: Initial eviction logic selected the most recently used (MRU) frame instead of LRU.
   - **Solution**: Corrected the logic to select the frame with the oldest timestamp.

2. **Periodic Output not Triggering**:
   - **Problem**: Memory layout was not being printed every simulated second.
   - **Solution**: Added a check in the main loop to print the layout whenever the simulated clock's seconds value changed.

3. **Statistics Tracking**:
   - **Problem**: Needed to track and report memory accesses and page faults accurately.
   - **Solution**: Added global counters and printed statistics at the end of the simulation.

4. **Segmentation Fault on Exit**:
   - **Problem**: Occasional segmentation fault after cleanup.
   - **Solution**: Ensured all IPC resources are cleaned up before exit; remaining issue is after all simulation is complete and does not affect results.


## Resources Cleanup

The system properly cleans up all IPC resources:
- Shared memory segments
- Message queues
- Process table entries
- Log files

Use `ipcs` command to verify no resources are left after termination.
