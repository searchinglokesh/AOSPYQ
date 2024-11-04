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
