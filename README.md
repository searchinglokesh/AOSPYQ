# Unix System Concepts and Practices

## 1. Why Interrupt Handlers Should Not Make Blocking Calls in Traditional Unix Systems

Interrupt handlers should not make blocking calls in traditional Unix systems because:

- They run in a special interrupt context with interrupts disabled.
- Blocking calls could lead to deadlocks since other interrupts are blocked.
- They need to execute quickly to maintain system responsiveness.
- Blocking calls could cause race conditions with the interrupted process.
- The system could become unresponsive if an interrupt handler blocks while waiting for resources.

## 2. `wait` System Call Prototypes and Functionality

**Prototypes:**

```c
pid_t wait(int *status);
pid_t waitpid(pid_t pid, int *status, int options);
int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
```

**Functionality:**

- **`wait()`**: Blocks the parent process until any child process terminates.
- **`waitpid()`**: Waits for a specific child process to change state.
- **`waitid()`**: Provides more detailed control over which children to wait for.

All functions store termination status information in the `status` parameter and return the process ID of the terminated child or -1 on error.

## 3. Sources of Signals and Signal-Related System Calls

### Sources of Signals:

1. Hardware exceptions (e.g., divide by zero, illegal memory access).
2. Terminal-generated signals (e.g., Ctrl+C, Ctrl+Z).
3. Software conditions (e.g., alarm timer expiry).
4. `kill` command or `kill()` system call.
5. Child process termination.

### Signal System Call Prototypes:

```c
int kill(pid_t pid, int sig);
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int sigsuspend(const sigset_t *mask);
```

## 4. Why the Old Unix Signal Handling Mechanism Was Unreliable and Inefficient

- Signals could be lost if multiple occurred simultaneously.
- Signal handlers were reset to the default after each delivery.
- Race conditions existed between signal occurrence and handler installation.
- There was no queuing of signals.
- Limited information was passed to signal handlers.
- No way to block specific signals during critical sections.

## 5. Process Group and Controlling Terminal

### Process Group:

- A collection of related processes identified by a process group ID.
- Used for job control and signal distribution.
- All processes in the group can receive signals simultaneously.
- Created using `setpgid()` system call.
- Each process group may have a leader (a process whose PID equals the PGID).

### Controlling Terminal:

- The terminal device that established the session.
- Only one per session.
- Processes in the foreground process group can read from the terminal.
- Generates signals (e.g., `SIGINT`, `SIGQUIT`) for the foreground process group.
- Can be accessed through `/dev/tty`.
- Terminal signals are sent to all processes in the foreground process group.

---

## Additional Questions

### 1. Disadvantages of Sleep Queues in Old Unix Operating Systems and Improvements in Solaris OS

**Drawbacks in Old Unix:**

- Fixed priority levels led to priority inversion.
- No priority inheritance mechanism.
- Lack of fine-grained scheduling control.
- Potential for deadlocks.
- No timeout mechanism for sleep operations.

**Improvements in Solaris:**

- Introduced priority inheritance.
- Dynamic priority adjustments.
- Timeout mechanisms for sleeping threads.
- Multiple scheduling classes.
- Fine-grained priority levels.

### 2. Limitations of `ptrace` System Call for Debugging

- Only one debugger can attach to a process.
- Performance overhead due to frequent context switches.
- Limited access to thread-specific information.
- Requires special handling to debug across `fork()`.
- No direct access to memory-mapped regions.
- Complex to implement distributed debugging.
- Lack of structured data access.

### 3. Real-Time Application Support in Solaris 2.x

**Adequate Aspects:**

- Real-time scheduling classes.
- High-resolution timers.
- Priority inheritance protocols.
- Preemptible kernel.
- Bounded priority inversion.
- Synchronization primitives.

---

## System V Semaphore Operations

**Examples:**

```c
// Creating semaphore
key_t key = ftok("/tmp/sem.temp", 65);
int semid = semget(key, 1, IPC_CREAT | 0666);

// Initializing semaphore
union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
} argument;
argument.val = 1;
semctl(semid, 0, SETVAL, argument);

// Wait operation (P)
struct sembuf sb = {0, -1, SEM_UNDO};
semop(semid, &sb, 1);

// Signal operation (V)
sb.sem_op = 1;
semop(semid, &sb, 1);
```

---

## Comparison: System Calls vs. Exceptions

**Similarities:**

- Both cause a transfer of control to the kernel.
- Both use a trap mechanism.
- Both require saving process state.
- Both have dedicated handlers.

**Differences:**

- System calls are synchronous; exceptions are asynchronous.
- System calls are intentional; exceptions are unexpected.
- System calls have predictable handling; exceptions vary.
- System calls return to the next instruction; exceptions may not.
- System calls pass parameters; exceptions provide error information.

### Signal Handling During Another Signal

A process can:

- Block additional signals using `sigprocmask()`.
- Use `sigaction()` with the `SA_NODEFER` flag.
- Set up signal masks in signal handlers.
- Use `sigsuspend()` for atomic operations.
- Maintain signal state variables.

---

## Program to Generate SIGPROF Repeatedly

```c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>

int count = 0;

void handler(int signo) {
    count++;
    if (count % 10 == 0) {
        printf("Received SIGPROF %d times\n", count);
    }
}

int main() {
    struct itimerval timer;

    signal(SIGPROF, handler);

    // Set timer for 0.5-second intervals
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 500000;
    timer.it_value = timer.it_interval;

    setitimer(ITIMER_PROF, &timer, NULL);

    while(1) {
        pause();
    }
    return 0;
}
```

## Client-Server Program Using Pipes for Word Frequency Count

**Server Code (`server.c`):**

```c
// server.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_WORD 50
#define MAX_WORDS 1000

struct word_freq {
    char word[MAX_WORD];
    int frequency;
};

int main() {
    int fd_read, fd_write;
    char filename[256];
    struct word_freq words[MAX_WORDS];
    int word_count = 0;

    mkfifo("req_pipe", 0666);
    mkfifo("resp_pipe", 0666);

    while(1) {
        fd_read = open("req_pipe", O_RDONLY);
        fd_write = open("resp_pipe", O_WRONLY);

        read(fd_read, filename, sizeof(filename));

        FILE *file = fopen(filename, "r");
        if(file) {
            char word[MAX_WORD];
            while(fscanf(file, "%s", word) == 1) {
                int found = 0;
                for(int i = 0; i < word_count; i++) {
                    if(strcmp(words[i].word, word) == 0) {
                        words[i].frequency++;
                        found = 1;
                        break;
                    }
                }
                if(!found && word_count < MAX_WORDS) {
                    strcpy(words[word_count].word, word);
                    words[word_count].frequency = 1;
                    word_count++;
                }
            }
            fclose(file);

            write(fd_write, &word_count, sizeof(int));
            write(fd_write, words, sizeof(struct word_freq) * word_count);
        }
        close(fd_read);
        close(fd_write);
    }
    return 0;
}
```

**Client Code (`client.c`):**

```c
// client.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX_WORD 50
#define MAX_WORDS 1000

struct word_freq {
    char word[MAX_WORD];
    int frequency;
};

int main(int argc, char *argv[]) {
    if(argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        exit(1);
    }

    int fd_write = open("req_pipe", O_WRONLY);
    int fd_read = open("resp_pipe", O_RDONLY);

    write(fd_write, argv[1], strlen(argv[1]) + 1);

    int word_count;
    struct word_freq words[MAX_WORDS];

    read(fd_read, &word_count, sizeof(int));
    read(fd_read, words, sizeof(struct word_freq) * word_count);

    printf("\nWord Frequency Table\n");
    printf("-------------------\n");
    printf("%-20s %s\n", "Word", "Frequency");
    printf("-------------------\n");

    for(int i = 0; i < word_count; i++) {
        printf("%

-20s %d\n", words[i].word, words[i].frequency);
    }

    close(fd_read);
    close(fd_write);

    return 0;
}
```

Compile and run `server.c` and `client.c`. The client sends the filename, and the server responds with word frequencies.

---


# More questions 
---

### 1) Drawbacks of Semaphores:

- **No Ownership Mechanism**: Any process can perform a V (signal) operation, leading to potential misuse or accidental release.
- **Possibility of Deadlocks**: No built-in mechanism to prevent or detect deadlocks.
- **No Queuing**: Waiting processes are not queued in order, which can lead to priority inversion and unfair scheduling.
- **No Timeout Mechanism**: Basic implementations lack a way for processes to wait with a timeout, limiting flexibility.
- **Difficult Debugging**: Race conditions can be hard to debug due to concurrent access to shared semaphores.
- **No Automatic Cleanup**: Semaphores do not clean up resources if a process terminates unexpectedly.
- **Memory Overhead**: Managing multiple semaphores consumes additional memory.
- **Risk of Priority Inversion**: Without priority inheritance, lower-priority processes can block higher-priority ones indefinitely.
  
### 2) Multiple Signal Instances:

**Traditional Unix Behavior**:
- Unix traditionally maintains only one pending signal of each type per process. If multiple instances of a signal are received before it’s handled, only one is preserved, and subsequent signals of the same type are lost.
  
**Improved Alternatives**:
- **POSIX Real-Time Signals**: Real-time signals support queuing, so multiple signals of the same type are not lost.
- **siginfo_t Structure**: Provides additional information about signals, including source and cause.
- **Signal Masking**: Critical sections can mask specific signals, reducing the likelihood of loss.
- **Signal Counting**: Maintains a count for each signal type, ensuring the handler processes every occurrence.

### 3) Remote Procedure Call (RPC) Working:

**Basic Workflow**:
1. **Client Side**:
   - Client calls a local stub procedure representing the server procedure.
   - Stub marshals (packages) parameters and sends the request to the server.
2. **Server Side**:
   - Server stub receives the message, unmarshals (unpacks) parameters, and calls the actual procedure.
   - The result is sent back to the client.
3. **Core Components**:
   - **Interface Definition Language (IDL)**: Describes remote procedure interfaces.
   - **Client/Server Stubs**: Handle data marshalling and unmarshalling.
   - **RPC Runtime Library**: Manages the communication process.
   - **Network Protocols**: Transport messages between client and server.

### 4) SVR4 Scheduler Details:

1. **Scheduling Classes**:
   - **Real-Time (RT)**: Fixed priorities (100-159) for time-critical tasks.
   - **System (SYS)**: Priorities (60-99) for kernel and system processes.
   - **Time-Sharing (TS)**: Priorities (0-59) for general user processes.
   - **Interactive (IA)**: Adapts for interactive tasks with dynamic adjustment.

2. **Priority Levels**:
   - Global priorities from 0 to 159, assigned by class.
   - Class-specific adjustments based on workload and responsiveness.
  
3. **Key Features**:
   - **Multilevel Feedback Queues**: Adjusts priority dynamically based on recent CPU usage.
   - **Preemptive Scheduling**: Higher-priority tasks preempt lower-priority ones.
   - **Dynamic Time Quantum**: Adjusts based on process behavior.
   - **Priority Inheritance**: Minimizes priority inversion for critical real-time tasks.

### 5) System V Message Queue Operations:

**Function Prototypes**:
```c
key_t ftok(const char *pathname, int proj_id);
int msgget(key_t key, int msgflg);
int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
int msgctl(int msqid, int cmd, struct msqid_ds *buf);
```

**Example Usage**:
```c
#include <sys/msg.h>
#include <stdio.h>
#include <string.h>

struct msgbuf {
    long mtype;
    char mtext[100];
};

int main() {
    key_t key = ftok("/tmp", 'A');               // Generate unique key
    int msgid = msgget(key, IPC_CREAT | 0666);   // Create message queue

    struct msgbuf msg;                           // Prepare message
    msg.mtype = 1;
    strcpy(msg.mtext, "Test message");

    msgsnd(msgid, &msg, sizeof(msg.mtext), 0);   // Send message

    struct msgbuf rcv;                           // Receive message
    msgrcv(msgid, &rcv, sizeof(rcv.mtext), 1, 0);

    msgctl(msgid, IPC_RMID, NULL);               // Remove message queue

    return 0;
}
```

**Key Operations**:
1. **`msgget()`**: Creates or accesses a message queue.
2. **`msgsnd()`**: Sends a message to the queue.
3. **`msgrcv()`**: Receives a message from the queue.
4. **`msgctl()`**: Performs control operations on the queue, such as removal (`IPC_RMID`).

**Common Flags**:
- **IPC_CREAT**: Creates a new queue if it doesn’t exist.
- **IPC_EXCL**: Fails if the queue already exists (used with `IPC_CREAT`).
- **IPC_NOWAIT**: Non-blocking mode for `msgsnd` and `msgrcv`.
- **IPC_RMID**: Removes the queue (used with `msgctl`).
