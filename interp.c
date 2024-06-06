#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <zlib.h>




int registers_count = 0;


char constant_names[50][50];
int constant_names_count = 0;

enum ConstantType{
	CONSTANT_INT,
	CONSTANT_STRING,
	CONSTANT_LEN,
	CONSTANT_METHOD,
	CONSTANT_EQ,
	CONSTANT_LTE,
	CONSTANT_LT,
	CONSTANT_GTE,
	CONSTANT_GT,
	CONSTANT_METHOD_END,
    CONSTANT_REGISTER_NAME, // Only when being ran
    CONSTANT_VAR            // Also only for when being ran
};

struct Constant{
	enum ConstantType type;
	uint8_t bytes[40]; 
};




enum InstructionType{
    INST_JMP,
	INST_MOV,
	INST_SYSCALL,
    INST_JNZ,
    INST_INC,
    INST_ADD,
	INST_SUB,
	INST_DEC,
	INST_IF,
	INST_IFEND
};


struct Instruction{
	uint8_t method[10];
	enum InstructionType type;
	int col, row;
	uint8_t operand1[10];
	struct Constant operand2;
};

#include "../libs/array/array.h"
#define constant struct Constant
new_arrtype(constant);

char *input_file;

struct Constant constants[50];
unsigned int constant_pool_count;
struct Constant methods[50];
arr_constant *registers;
struct Instruction instructions[50];
arr_constant *variables;


struct syscall_info {
    int number;
    const char *name;
    const char *description;
};

struct syscall_info syscall_list[] = {
	    {0, "sys_read", "Read data from a file descriptor"},
    {1, "sys_write", "Write data to a file descriptor"},
    {2, "sys_open", "Open a file"},
    {3, "sys_close", "Close a file descriptor"},
    {4, "sys_stat", "Get file status"},
    {5, "sys_fstat", "Get file status of a specified file descriptor"},
    {6, "sys_lstat", "Get file status by following symbolic links"},
    {7, "sys_poll", "Poll a set of file descriptors"},
    {8, "sys_lseek", "Change the file offset"},
    {9, "sys_mmap", "Map files or devices into memory"},
    {10, "sys_mprotect", "Change memory protections"},
    {11, "sys_munmap", "Unmap files or devices from memory"},
    {12, "sys_brk", "Change the location of the program break"},
    {13, "sys_rt_sigaction", "Set signal action for real-time signals"},
    {14, "sys_rt_sigprocmask", "Change blocked signals"},
    {15, "sys_rt_sigreturn", "Return from a signal handler"},
    {16, "sys_ioctl", "Perform device-specific operations"},
    {17, "sys_pread64", "Read data from a file descriptor into a buffer"},
    {18, "sys_pwrite64", "Write data from a buffer to a file descriptor"},
    {19, "sys_readv", "Read data into multiple buffers from a file descriptor"},
    {20, "sys_writev", "Write data from multiple buffers to a file descriptor"},
    {21, "sys_access", "Check if a file exists and has permission"},
    {22, "sys_pipe", "Create an interprocess communication pipe"},
    {23, "sys_select", "Synchronous I/O multiplexing"},
    {24, "sys_sched_yield", "Yield the processor voluntarily"},
    {25, "sys_mremap", "Remap a virtual memory address"},
    {26, "sys_msync", "Synchronize a file with a memory map"},
    {27, "sys_mincore", "Determine whether pages are resident in memory"},
    {28, "sys_madvise", "Provide advice about use of memory mappings"},
    {29, "sys_shmget", "Allocate a shared memory segment"},
    {30, "sys_shmat", "Attach a shared memory segment"},
    {31, "sys_shmctl", "Control shared memory"},
    {32, "sys_dup", "Duplicate a file descriptor"},
    {33, "sys_dup2", "Duplicate a file descriptor to a specified one"},
    {34, "sys_pause", "Suspend the process until a signal is received"},
    {35, "sys_nanosleep", "Sleep for a specified interval of time"},
    {36, "sys_getitimer", "Get the value of an interval timer"},
    {37, "sys_alarm", "Set an alarm clock for delivery of a signal"},
    {38, "sys_setitimer", "Set the value of an interval timer"},
    {39, "sys_getpid", "Get the process ID"},
    {40, "sys_sendfile", "Send data between file descriptors"},
    {41, "sys_socket", "Create a new socket"},
    {42, "sys_connect", "Initiate a connection on a socket"},
    {43, "sys_accept", "Accept a connection on a socket"},
    {44, "sys_sendto", "Send data to a socket"},
    {45, "sys_recvfrom", "Receive data from a socket"},
    {46, "sys_sendmsg", "Send a message on a socket"},
    {47, "sys_recvmsg", "Receive a message from a socket"},
    {48, "sys_shutdown", "Shut down part of a full-duplex connection"},
    {49, "sys_bind", "Bind a name to a socket"},
    {50, "sys_listen", "Listen for connections on a socket"},
    {51, "sys_getsockname", "Get the name of the socket"},
    {52, "sys_getpeername", "Get the name of the connected peer socket"},
    {53, "sys_socketpair", "Create a pair of connected sockets"},
    {54, "sys_setsockopt", "Set options on a socket"},
    {55, "sys_getsockopt", "Get options from a socket"},
    {56, "sys_clone", "Create a new process"},
    {57, "sys_fork", "Create a new process (deprecated)"},
    {58, "sys_vfork", "Create a new process in a suspended state"},
    {59, "sys_execve", "Execute a program"},
    {60, "sys_exit", "Terminate the calling process"},
    {61, "sys_wait4", "Wait for process termination and collect its status"},
    {62, "sys_kill", "Send a signal to a process"},
    {63, "sys_uname", "Get system information"},
    {64, "sys_semget", "Get a semaphore set identifier"},
    {65, "sys_semop", "Perform semaphore operations"},
    {66, "sys_semctl", "Control semaphore sets"},
    {67, "sys_shmdt", "Detach a shared memory segment"},
    {68, "sys_msgget", "Get a message queue identifier"},
    {69, "sys_msgsnd", "Send a message to a message queue"},
    {70, "sys_msgrcv", "Receive a message from a message queue"},
    {71, "sys_msgctl", "Control message queues"},
    {72, "sys_fcntl", "Perform file control operations"},
    {73, "sys_flock", "Apply or remove an advisory lock on an open file"},
    {74, "sys_fsync", "Synchronize a file's in-core state with storage device"},
    {75, "sys_fdatasync", "Synchronize a file's in-core data with storage device"},
    {76, "sys_truncate", "Truncate a file to a specified length"},
    {77, "sys_ftruncate", "Truncate a file to a specified length (specified by file descriptor)"},
    {78, "sys_getdents", "Get directory entries"},
    {79, "sys_getcwd", "Get the current working directory"},
    {80, "sys_chdir", "Change the current working directory"},
    {81, "sys_fchdir", "Change the current working directory (specified by file descriptor)"},
    {82, "sys_rename", "Rename a file"},
    {83, "sys_mkdir", "Create a directory"},
    {84, "sys_rmdir", "Remove a directory"},
    {85, "sys_creat", "Create a file"},
    {86, "sys_link", "Create a hard link"},
    {87, "sys_unlink", "Remove a directory entry"},
    {88, "sys_symlink", "Create a symbolic link"},
    {89, "sys_readlink", "Read the value of a symbolic link"},
    {90, "sys_chmod", "Change the permissions of a file"},
    {91, "sys_fchmod", "Change the permissions of a file (specified by file descriptor)"},
    {92, "sys_chown", "Change the ownership of a file"},
    {93, "sys_fchown", "Change the ownership of a file (specified by file descriptor)"},
    {94, "sys_lchown", "Change the ownership of a file (without following symbolic links)"},
    {95, "sys_umask", "Set the file mode creation mask"},
    {96, "sys_gettimeofday", "Get the current time and timezone"},
    {97, "sys_getrlimit", "Get resource limits"},
    {98, "sys_getrusage", "Get resource usage"},
    {99, "sys_sysinfo", "Get system information"},
    {100, "sys_times", "Get process times"},
    {101, "sys_ptrace", "Process tracing and debugging"},
    {102, "sys_getuid", "Get the real user ID"},
    {103, "sys_syslog", "Write a message to the system logger"},
    {104, "sys_getgid", "Get the real group ID"},
    {105, "sys_setuid", "Set the real user ID"},
    {106, "sys_setgid", "Set the real group ID"},
    {107, "sys_geteuid", "Get the effective user ID"},
    {108, "sys_getegid", "Get the effective group ID"},
    {109, "sys_setpgid", "Set the process group ID"},
    {110, "sys_getppid", "Get the parent process ID"},
    {111, "sys_getpgrp", "Get the process group ID"},
    {112, "sys_setsid", "Create a new session and set the process group ID"},
    {113, "sys_setreuid", "Set the real and effective user IDs"},
    {114, "sys_setregid", "Set the real and effective group IDs"},
    {115, "sys_getgroups", "Get supplementary group IDs"},
    {116, "sys_setgroups", "Set supplementary group IDs"},
    {117, "sys_setresuid", "Set the real, effective, and saved user IDs"},
    {118, "sys_getresuid", "Get real, effective, and saved user IDs"},
    {119, "sys_setresgid", "Set the real, effective, and saved group IDs"},
    {120, "sys_getresgid", "Get real, effective, and saved group IDs"},
    {121, "sys_getpgid", "Get the process group ID of a process"},
    {122, "sys_setfsuid", "Set the filesystem user ID"},
    {123, "sys_setfsgid", "Set the filesystem group ID"},
    {124, "sys_getsid", "Get the session ID"},
    {125, "sys_capget", "Get process capabilities"},
    {126, "sys_capset", "Set process capabilities"},
    {127, "sys_rt_sigpending", "Get pending real-time signals"},
    {128, "sys_rt_sigtimedwait", "Wait for queued signals"},
    {129, "sys_rt_sigqueueinfo", "Queue a real-time signal and data"},
    {130, "sys_rt_sigsuspend", "Suspend the process until a signal is received"},
    {131, "sys_sigaltstack", "Alternate signal stack"},
    {132, "sys_utime", "Change file access and modification times"},
    {133, "sys_mknod", "Create a special or ordinary file"},
    {134, "sys_uselib", "Use shared library (unused)"},
    {135, "sys_personality", "Set the process execution domain"},
    {136, "sys_ustat", "Get filesystem statistics"},
    {137, "sys_statfs", "Get filesystem statistics"},
    {138, "sys_fstatfs", "Get filesystem statistics of a specified file descriptor"},
    {139, "sys_sysfs", "Manipulate kernel parameters"},
    {140, "sys_getpriority", "Get process scheduling priority"},
    {141, "sys_setpriority", "Set process scheduling priority"},
    {142, "sys_sched_setparam", "Set scheduling parameters"},
    {143, "sys_sched_getparam", "Get scheduling parameters"},
    {144, "sys_sched_setscheduler", "Set scheduling policy and parameters"},
    {145, "sys_sched_getscheduler", "Get scheduling policy"},
    {146, "sys_sched_get_priority_max", "Get maximum scheduling priority for a policy"},
    {147, "sys_sched_get_priority_min", "Get minimum scheduling priority for a policy"},
    {148, "sys_sched_rr_get_interval", "Get the time slice for a process under Round Robin scheduling"},
    {149, "sys_mlock", "Lock a range of memory pages"},
    {150, "sys_munlock", "Unlock a range of memory pages"},
    {151, "sys_mlockall", "Lock all memory pages mapped by the process"},
    {152, "sys_munlockall", "Unlock all memory pages mapped by the process"},
    {153, "sys_vhangup", "Simulate a hang-up on a terminal"},
    {154, "sys_modify_ldt", "Change the global and local descriptor tables"},
    {155, "sys_pivot_root", "Change the root filesystem"},
    {156, "sys__sysctl", "Read/write system parameters"},
    {157, "sys_prctl", "Control process parameters"},
    {158, "sys_arch_prctl", "Adjust process architecture-specific settings"},
    {159, "sys_adjtimex", "Tune kernel time variables"},
    {160, "sys_setrlimit", "Set resource limits"},
    {161, "sys_chroot", "Change the root directory"},
    {162, "sys_sync", "Synchronize cached writes to persistent storage"},
    {163, "sys_acct", "Enable or disable process accounting"},
    {164, "sys_settimeofday", "Set the system time and timezone"},
    {165, "sys_mount", "Mount filesystem"},
    {166, "sys_umount2", "Unmount filesystem"},
    {167, "sys_swapon", "Enable or disable swapping to a specified device"},
    {168, "sys_swapoff", "Disable swapping on a specified device"},
    {169, "sys_reboot", "Reboot or halt the system"},
    {170, "sys_sethostname", "Set the system hostname"},
    {171, "sys_setdomainname", "Set the system domainname"},
    {172, "sys_iopl", "Change I/O privilege level"},
    {173, "sys_ioperm", "Allow or deny access to I/O ports"},
    {174, "sys_create_module", "Create a kernel module (unused)"},
    {175, "sys_init_module", "Load a kernel module"},
    {176, "sys_delete_module", "Unload a kernel module"},
    {177, "sys_get_kernel_syms", "Get exported kernel symbols"},
    {178, "sys_query_module", "Query information about a kernel module (unused)"},
    {179, "sys_quotactl", "Control disk quotas"},
    {180, "sys_nfsservctl", "NFS server management"},
    {181, "sys_getpmsg", "Receive a message from a POSIX message queue"},
    {182, "sys_putpmsg", "Send a message to a POSIX message queue"},
    {183, "sys_afs_syscall", "Unimplemented syscall for AFS (unused)"},
    {184, "sys_tuxcall", "Unimplemented TUX syscall (unused)"},
    {185, "sys_security", "Security operation"},
    {186, "sys_gettid", "Get the thread ID"},
    {187, "sys_readahead", "Read ahead in a file"},
    {188, "sys_setxattr", "Set an extended attribute value of a file"},
    {189, "sys_lsetxattr", "Set an extended attribute value of a file (without following symbolic links)"},
    {190, "sys_fsetxattr", "Set an extended attribute value of a file (specified by file descriptor)"},
    {191, "sys_getxattr", "Get an extended attribute value of a file"},
    {192, "sys_lgetxattr", "Get an extended attribute value of a file (without following symbolic links)"},
    {193, "sys_fgetxattr", "Get an extended attribute value of a file (specified by file descriptor)"},
    {194, "sys_listxattr", "List extended attribute keys of a file"},
    {195, "sys_llistxattr", "List extended attribute keys of a file (without following symbolic links)"},
    {196, "sys_flistxattr", "List extended attribute keys of a file (specified by file descriptor)"},
    {197, "sys_removexattr", "Remove an extended attribute from a file"},
    {198, "sys_lremovexattr", "Remove an extended attribute from a file (without following symbolic links)"},
    {199, "sys_fremovexattr", "Remove an extended attribute from a file (specified by file descriptor)"},
    {200, "sys_tkill", "Send a signal to a thread"},
    {201, "sys_time", "Get the time in seconds since the Epoch"},
    {202, "sys_futex", "Fast user-space mutex"},
    {203, "sys_sched_setaffinity", "Set CPU affinity"},
    {204, "sys_sched_getaffinity", "Get CPU affinity"},
    {205, "sys_set_thread_area", "Set a thread-local storage (TLS) area"},
    {206, "sys_io_setup", "Create an asynchronous I/O context"},
    {207, "sys_io_destroy", "Destroy an asynchronous I/O context"},
    {208, "sys_io_getevents", "Retrieve the result of asynchronous I/O operations"},
    {209, "sys_io_submit", "Submit asynchronous I/O operations"},
    {210, "sys_io_cancel", "Cancel asynchronous I/O operations"},
    {211, "sys_get_thread_area", "Get a thread-local storage (TLS) area"},
    {212, "sys_lookup_dcookie", "Get a directory entry's cookie"},
    {213, "sys_epoll_create", "Create an epoll file descriptor"},
    {214, "sys_epoll_ctl_old", "Control an epoll file descriptor (deprecated)"},
    {215, "sys_epoll_wait_old", "Wait for events on an epoll file descriptor (deprecated)"},
    {216, "sys_remap_file_pages", "Remap a range of memory pages"},
    {217, "sys_getdents64", "Get directory entries with large file support"},
    {218, "sys_set_tid_address", "Set the thread ID pointer"},
    {219, "sys_restart_syscall", "Restart a system call after interruption"},
    {220, "sys_semtimedop", "Perform semaphore operations with a timeout"},
    {221, "sys_fadvise64", "Provide advice about use of file data"},
    {222, "sys_timer_create", "Create a POSIX per-process timer"},
    {223, "sys_timer_settime", "Set the time until the next expiration of a POSIX per-process timer"},
    {224, "sys_timer_gettime", "Get the time until the next expiration of a POSIX per-process timer"},
    {225, "sys_timer_getoverrun", "Get the number of missed expirations of a POSIX per-process timer"},
    {226, "sys_timer_delete", "Delete a POSIX per-process timer"},
    {227, "sys_clock_settime", "Set the time of a clock"},
    {228, "sys_clock_gettime", "Get the time of a clock"},
    {229, "sys_clock_getres", "Get the resolution of a clock"},
    {230, "sys_clock_nanosleep", "Sleep for a specified interval of time with a specified clock"},
    {231, "sys_exit_group", "Terminate all threads in the calling process"},
    {232, "sys_epoll_wait", "Wait for events on an epoll file descriptor"},
    {233, "sys_epoll_ctl", "Control an epoll file descriptor"},
    {234, "sys_tgkill", "Send a signal to a thread in another process"},
    {235, "sys_utimes", "Change file access and modification times with nanosecond precision"},
    {236, "sys_vserver", "Virtual server operation (unused)"},
    {237, "sys_mbind", "Bind a memory policy to a memory range"},
    {238, "sys_set_mempolicy", "Set the default memory policy for a process"},
    {239, "sys_get_mempolicy", "Retrieve the default memory policy for a process"},
    {240, "sys_mq_open", "Create or open a POSIX message queue"},
    {241, "sys_mq_unlink", "Remove a POSIX message queue"},
    {242, "sys_mq_timedsend", "Send a message to a POSIX message queue with a timeout"},
    {243, "sys_mq_timedreceive", "Receive a message from a POSIX message queue with a timeout"},
    {244, "sys_mq_notify", "Register a notification for a POSIX message queue"},
    {245, "sys_mq_getsetattr", "Get or set the attributes of a POSIX message queue"},
    {246, "sys_kexec_load", "Load a new kernel for later execution"},
    {247, "sys_waitid", "Wait for process termination and get its process and resource usage information"},
    {248, "sys_add_key", "Add a key to the kernel's key management facility"},
    {249, "sys_request_key", "Request a key from the kernel's key management facility"},
    {250, "sys_keyctl", "Control key management facilities"},
    {251, "sys_ioprio_set", "Set I/O scheduling class and priority for a process"},
    {252, "sys_ioprio_get", "Get I/O scheduling class and priority for a process"},
    {253, "sys_inotify_init", "Initialize an inotify instance"},
    {254, "sys_inotify_add_watch", "Add a watch to an inotify instance"},
    {255, "sys_inotify_rm_watch", "Remove a watch from an inotify instance"},
    {256, "sys_migrate_pages", "Move memory pages between nodes"},
    {257, "sys_openat", "Open a file relative to a directory file descriptor"},
    {258, "sys_mkdirat", "Create a directory relative to a directory file descriptor"},
    {259, "sys_mknodat", "Create a special or ordinary file relative to a directory file descriptor"},
    {260, "sys_fchownat", "Change the ownership of a file relative to a directory file descriptor"},
    {261, "sys_futimesat", "Change file access and modification times relative to a directory file descriptor"},
    {262, "sys_newfstatat", "Get file status relative to a directory file descriptor"},
    {263, "sys_unlinkat", "Remove a directory entry relative to a directory file descriptor"},
    {264, "sys_renameat", "Rename a file relative to a directory file descriptor"},
    {265, "sys_linkat", "Create a hard link relative to a directory file descriptor"},
    {266, "sys_symlinkat", "Create a symbolic link relative to a directory file descriptor"},
    {267, "sys_readlinkat", "Read the value of a symbolic link relative to a directory file descriptor"},
    {268, "sys_fchmodat", "Change the permissions of a file relative to a directory file descriptor"},
    {269, "sys_faccessat", "Check if a file exists and has permission relative to a directory file descriptor"},
    {270, "sys_pselect6", "Synchronous I/O multiplexing with a timeout"},
    {271, "sys_ppoll", "Poll for I/O events with a timeout"},
    {272, "sys_unshare", "Create a new namespace"},
    {273, "sys_set_robust_list", "Set the list of robust futexes"},
    {274, "sys_get_robust_list", "Get the list of robust futexes"},
    {275, "sys_splice", "Move data between file descriptors"},
    {276, "sys_tee", "Duplicate data between two file descriptors"},
    {277, "sys_sync_file_range", "Synchronize file data with storage device"},
    {278, "sys_vmsplice", "Move data between kernel and user space"},
    {279, "sys_move_pages", "Move memory pages between nodes and control migration"},
    {280, "sys_utimensat", "Change file access and modification times with nanosecond precision relative to a directory file descriptor"},
    {281, "sys_epoll_pwait", "Wait for events on an epoll file descriptor with a timeout"},
    {282, "sys_signalfd", "Create a file descriptor for accepting signals"},
    {283, "sys_timerfd_create", "Create a timer file descriptor"},
    {284, "sys_eventfd", "Create a file descriptor for event notification"},
    {285, "sys_fallocate", "Allocate space for a file"},
    {286, "sys_timerfd_settime", "Set the time until the next expiration of a timer file descriptor"},
    {287, "sys_timerfd_gettime", "Get the time until the next expiration of a timer file descriptor"},
    {288, "sys_accept4", "Accept a connection on a socket with flags"},
    {289, "sys_signalfd4", "Create a file descriptor for accepting signals with flags"},
    {290, "sys_eventfd2", "Create a file descriptor for event notification with flags"},
    {291, "sys_epoll_create1", "Create an epoll file descriptor with flags"},
    {292, "sys_dup3", "Duplicate a file descriptor to a specified one with flags"},
    {293, "sys_pipe2", "Create an interprocess communication pipe with flags"},
    {294, "sys_inotify_init1", "Initialize an inotify instance with flags"},
    {295, "sys_preadv", "Read data into multiple buffers from a file descriptor with offset"},
    {296, "sys_pwritev", "Write data from multiple buffers to a file descriptor with offset"},
    {297, "sys_rt_tgsigqueueinfo", "Send a signal to a thread group"},
    {298, "sys_perf_event_open", "Open a performance monitoring event"},
    {299, "sys_recvmmsg", "Receive multiple messages from a socket with flags"},
};



char *getNthLine(const char *str, int n) {
    if (str == NULL || n < 1) {
        return NULL;
    }

    const char *start = str;
    int current_line = 1;

    // Iterate through the string to find the nth line
    while (*start != '\0' && current_line < n) {
        if (*start == '\n') {
            current_line++;
        }
        start++;
    }

    if (current_line != n) {
        return NULL; // The nth line doesn't exist in the string
    }

    // Find the end of the nth line
    const char *end = strchr(start, '\n');
    if (end == NULL) {
        return strdup(start); // Return the rest of the string if there are no more newline characters
    }

    // Calculate the length of the nth line
    size_t length = end - start;

    // Allocate memory for the line
    char *line = (char *)malloc(length + 1);
    if (line == NULL) {
        return NULL; // Memory allocation error
    }

    // Copy the nth line from start to end
    memcpy(line, start, length);
    line[length] = '\0'; // Null-terminate the string

    return line;
}

#define print_ln_error(code, strt, end, col, row, showend)  \
		char *line = "\tsyscall"; \
		char ln[50]; \ 
		sprintf(ln, "%d", row+1); \
		for (int i=0; i<=strlen(ln); i++){ \
			printf(" "); \
		}; \
		printf("\e[0;30m|\e[0m\n", row+1, line); \
		printf("\e[0;30m%d | \e[0m%s%s%s\n", row+1, strt, line, end); \
		if (showend == 1) {for (int i=0; i<=strlen(ln); i++){ \
			printf(" "); \
		}; \
		printf("\e[0;30m|\e[0m", row+1, line); \
        printf("\t"); \
		printf("\e[0;30m^"); \
		for (int i=1; i<=strlen(code)-1; i++){ \
			printf("~"); \
		}; \
		printf("\e[0m\n"); }



void error(char *info, char* type, struct Instruction instruction){
        // fprintf(stderr, "%s", "Hoi");
	printf("\e[1;37m%s:%d:%d\e[0m: ", input_file, instruction.row+1, instruction.col);
	printf("\e[0;31m%s\e[0m: \e[1;37m%s\e[0m\n", type, info);
    print_ln_error("syscall", "", "", instruction.col, instruction.row, 1);
    printf("Note: Instruction converted into human-readable format for your convenience.\n");
	exit(1);
};


void help(){
	printf("Bytecode EMULATOR:\n");
	printf("	-h: Prints this manual\n");
}

int gettype(char *b){
    if(b[0] == '\"'){return CONSTANT_STRING;}
    else if(isnumber(b[0])){return CONSTANT_INT;}
    else{return CONSTANT_VAR;};
};

char *parse(struct Constant cons){
    char *data = cons.bytes;
    if (strcmp(data, "rax") == 0 || strcmp(data, "rbx") == 0 || strcmp(data, "rcx") == 0 || strcmp(data, "rdx") == 0 || strcmp(data, "rsp") == 0 || strcmp(data, "rbp") == 0 || strcmp(data, "rsi") == 0 || strcmp(data, "rdi") == 0 || strcmp(data, "r10") == 0 || strcmp(data, "r11") == 0 || strcmp(data, "r12") == 0){
        for (int i=0; i<=registers->len; i+=2){
            if (strcmp(registers->value[i].bytes, data) == 0){
                if (registers->value[i].type == CONSTANT_LEN){
                    sprintf(data, "%d", strlen(parse(registers->value[i])));
                    return data;
                };
                return parse(registers->value[i+1]);
            };
        };
    };
    if (cons.type == CONSTANT_INT){
        return data;
    };
    if (cons.type == CONSTANT_EQ){
        char *conbytecpy = strdup(cons.bytes);
        char *a = strtok(conbytecpy, "^(*&");
        struct Constant con;
        con.type = CONSTANT_VAR;
        memcpy(con.bytes, a, sizeof(con.bytes));
        char *b = cons.bytes+strlen(a)+strlen("^(*&");
        struct Constant con2;
        con2.type = gettype(b);
        memcpy(con2.bytes, b, sizeof(con2.bytes));
        char datas[50];
        unsigned int ab = strcmp(parse(con), parse(con2)) == 0;
        sprintf(datas, "%d", ab);
        data = strdup(datas);
        return data;
    }else if (cons.type == CONSTANT_LT){
        char *conbytecpy = strdup(cons.bytes);
        char *a = strtok(conbytecpy, "^(*&");
        struct Constant con;
        con.type = CONSTANT_VAR;
        memcpy(con.bytes, a, sizeof(con.bytes));
        char *b = cons.bytes+strlen(a)+strlen("^(*&");
        struct Constant con2;
        con2.type = gettype(b);
        memcpy(con2.bytes, b, sizeof(con2.bytes));
        char datas[50];
        unsigned int ab = atoi(parse(con)) < atoi(parse(con2));
        sprintf(datas, "%d", ab);
        data = strdup(datas);
        return data;
    }else if (cons.type == CONSTANT_LTE){
        char *conbytecpy = strdup(cons.bytes);
        char *a = strtok(conbytecpy, "^(*&");
        struct Constant con;
        con.type = gettype(a);
        memcpy(con.bytes, a, sizeof(con.bytes));
        char *b = cons.bytes+strlen(a)+strlen("^(*&");
        struct Constant con2;
        con2.type = gettype(b);
        memcpy(con2.bytes, b, sizeof(con2.bytes));
        char datas[50];
        unsigned int ab = atoi(parse(con)) <= atoi(parse(con2));
        sprintf(datas, "%d", ab);
        data = strdup(datas);
        return data;
    }else if (cons.type == CONSTANT_GT){
        char *conbytecpy = strdup(cons.bytes);
        char *a = strtok(conbytecpy, "^(*&");
        struct Constant con;
        con.type = CONSTANT_VAR;
        memcpy(con.bytes, a, sizeof(con.bytes));
        char *b = cons.bytes+strlen(a)+strlen("^(*&");
        struct Constant con2;
        con2.type = gettype(b);
        memcpy(con2.bytes, b, sizeof(con2.bytes));
        char datas[50];
        unsigned int ab = atoi(parse(con)) > atoi(parse(con2));
        sprintf(datas, "%d", ab);
        data = strdup(datas);
        return data;
    }else if (cons.type == CONSTANT_GTE){
        char *conbytecpy = strdup(cons.bytes);
        char *a = strtok(conbytecpy, "^(*&");
        struct Constant con;
        con.type = CONSTANT_VAR;
        memcpy(con.bytes, a, sizeof(con.bytes));
        char *b = cons.bytes+strlen(a)+strlen("^(*&");
        struct Constant con2;
        con2.type = gettype(b);
        memcpy(con2.bytes, b, sizeof(con2.bytes));
        char datas[50];
        unsigned int ab = atoi(parse(con)) >= atoi(parse(con2));
        sprintf(datas, "%d", ab);
        data = strdup(datas);
        return data;
    };
    if (data[0] == '"'){
        data++;
        return data;
    };
    for (int i=0; i<=constant_names_count; i++){
        if (strcmp(constant_names[i], data) == 0){
            if (constants[i].type == CONSTANT_LEN){
                sprintf(data, "%d", strlen(parse(constants[i])));
                return data;
            };
            return parse(constants[i]);
        };
    };
    for (int i=0; i<=registers->len; i+=2){
        if (strcmp(registers->value[i].bytes, data) == 0){
            if (registers->value[i].type == CONSTANT_LEN){
                sprintf(data, "%d", strlen(parse(registers->value[i])));
                return data;
            };
            return parse(registers->value[i+1]);
        };
    };
    for (int i=0; i<=variables->len; i+=2){
        if (strcmp(variables->value[i].bytes, data) == 0){
            if (variables->value[i].type == CONSTANT_LEN){
                sprintf(data, "%d", strlen(parse(variables->value[i])));
                return data;
            };
            return parse(variables->value[i+1]);
        };
    };
    data = cons.bytes;
    return data;
};

void run1(int i, int *pass, int instruction_count);
#include <stdbool.h>
bool inIfStatement = false;
bool goThroughIfStatement = false;

void run1(int i, int *pass, int instruction_count){
    if (instructions[i].type == INST_IFEND){
        inIfStatement = false;
        goThroughIfStatement = false;
    };
    // printf("{%d}", instructions[i].type);
    if (inIfStatement && !goThroughIfStatement){
        return;
    };
    if (strcmp(instructions[i].method, "main") && *pass == 0){
                return;
            };

        if (instructions[i].type == INST_MOV){
            int found = 0;
            for (int z=0; z<=registers->len; z+=2){
                if (strcmp(registers->value[z].bytes, instructions[i].operand1) == 0){
                    found = 1;
                    strcpy(registers->value[z+1].bytes, parse(instructions[i].operand2));
                    if(isalpha(parse(instructions[i].operand2)[0])) {
                        registers->value[z+1].type = CONSTANT_STRING;
                    } else {
                        registers->value[z+1].type = instructions[i].operand2.type;
                    }
                };
            };
            if (found == 0){
                struct Constant s;
				s.type = CONSTANT_METHOD;
				strcpy(s.bytes, instructions[i].operand1);
				arr_push(variables, s);
				if (parse(instructions[i].operand2)[0] == '"'){
					s.type = CONSTANT_STRING;
				}else {
					s.type = CONSTANT_INT;
				};
				strcpy(s.bytes, parse(instructions[i].operand2));
				arr_push(variables, s);
            };
        }else if (instructions[i].type == INST_SYSCALL){
			char *rax = (char*)arr_get(registers, 1).bytes;
			char *rdi = (char*)arr_get(registers, 15).bytes;
			char *rsi = (char*)arr_get(registers, 13).bytes;
			char *rdx = (char*)arr_get(registers, 7).bytes;
			if (atoi(rax) == 0) {
				char *buf;
				read(atoi(rdi), buf, atoi(rdx));
				sprintf(arr_get(registers, 1).bytes, "%s", buf);
			}else if (atoi(rax) == 1) {
				write(atoi(rdi), rsi, atoi(rdx));
			}else if (atoi(rax) == 2) {
				sprintf(arr_get(registers, 1).bytes, "%d", open(rdi, O_RDWR | O_CREAT));
			}else if (atoi(rax) == 3) {
				close(atoi(rdi));
			}else if (atoi(rax) == 60) {
				exit(atoi(rdi));
			}else {
                char err[500];

                int found = 0;
                for(int i=0; i<=sizeof(syscall_list)/sizeof(syscall_list[0]); i++){
                    if (syscall_list[i].number == atoi(rax)){
                        found = 1;
                    };
                };
                if (found == 0) {
					sprintf(err, "Syscall number %d does not exist", atoi(rax));
                }else if (found == 1) {
					sprintf(err, "Syscall number %d is not implemented", atoi(rax));
                }
					error(err, "SyscallError", instructions[i]);
            }
        }else if(instructions[i].type == INST_IF){
            inIfStatement = true;
            goThroughIfStatement = strcmp(parse(instructions[i].operand2), "1") == 0;
        }else if(instructions[i].type == INST_INC){
            for (int z=0; z<=registers->len; z+=2){
                if (strcmp(registers->value[z].bytes, instructions[i].operand1) == 0){
                    if (arr_get(registers, z+1).type == CONSTANT_INT) {
					sprintf(arr_get(registers, z+1).bytes, "%d", atoi(arr_get(registers, z+1).bytes)+1);
                    }else if(arr_get(registers, z+1).type == CONSTANT_STRING){
                        char *bytes = strdup(arr_get(registers, z+1).bytes);
                        bytes++;
                        strcpy(arr_get(registers, z+1).bytes, bytes);
                    }
                };
            };
        }else if(instructions[i].type == INST_DEC){
            for (int z=0; z<=registers->len; z+=2){
                if (strcmp(registers->value[z].bytes, instructions[i].operand1) == 0){
                    if (arr_get(registers, z+1).type == CONSTANT_INT) {
					sprintf(arr_get(registers, z+1).bytes, "%d", atoi(arr_get(registers, z+1).bytes)-1);
                    }else if(arr_get(registers, z+1).type == CONSTANT_STRING){
                        char *bytes = arr_get(registers, z+1).bytes;
                        bytes--;
                        strcpy(arr_get(registers, z+1).bytes, bytes);
                    }
                };
            };
        }else if(instructions[i].type == INST_ADD){
            for (int z=0; z<=registers->len; z+=2){
                if (strcmp(registers->value[z].bytes, instructions[i].operand1) == 0){
                    if (arr_get(registers, z+1).type == CONSTANT_INT) {
					sprintf(arr_get(registers, z+1).bytes, "%d", atoi(arr_get(registers, z+1).bytes)+atoi(instructions[i].operand2.bytes));
                    }else if(arr_get(registers, z+1).type == CONSTANT_STRING){
                        char *bytes = strdup(arr_get(registers, z+1).bytes);
                        bytes+=atoi(instructions[i].operand2.bytes);
                        strcpy(arr_get(registers, z+1).bytes, bytes);
                    }
                };
            };
        }else if(instructions[i].type == INST_SUB){
            for (int z=0; z<=registers->len; z+=2){
                if (strcmp(registers->value[z].bytes, instructions[i].operand1) == 0){
                    if (arr_get(registers, z+1).type == CONSTANT_INT) {
					sprintf(arr_get(registers, z+1).bytes, "%d", atoi(arr_get(registers, z+1).bytes)-atoi(instructions[i].operand2.bytes));
                    }else if(arr_get(registers, z+1).type == CONSTANT_STRING){
                        char *bytes = strdup(arr_get(registers, z+1).bytes);
                        bytes-=atoi(instructions[i].operand2.bytes);
                        strcpy(arr_get(registers, z+1).bytes, bytes);
                    }
                };
            };
        }else if(instructions[i].type == INST_JMP){
            *pass = 1;
            for (int j=0; j<=instruction_count; j++){
                if (strcmp(instructions[j].method, instructions[i].operand1)){
                    continue;
                }
                    run1(j, pass, instruction_count);
            }
            *pass = 0;
        }else if(instructions[i].type == INST_JNZ){
				if (atoi(arr_get(registers, 1).bytes)==0){
					return;
				};
            *pass = 1;
            for (int j=0; j<=instruction_count; j++){
                if (strcmp(instructions[j].method, instructions[i].operand1)){
                    continue;
                }
                    run1(j, pass, instruction_count);
            }
            *pass = 0;
        };
};

void run(char *input_file){
    // fprintf(stderr, "{1}");
    registers = arr_new(constant);
    variables = arr_new(constant);
    constant a = {CONSTANT_REGISTER_NAME, "rax"};
    constant b = {CONSTANT_REGISTER_NAME, "rbx"};
    constant c = {CONSTANT_REGISTER_NAME, "rcx"};
    constant d = {CONSTANT_REGISTER_NAME, "rdx"};
    constant e = {CONSTANT_REGISTER_NAME, "rsp"};
    constant rf = {CONSTANT_REGISTER_NAME, "rbp"};
    constant g = {CONSTANT_REGISTER_NAME, "rsi"};
    constant h = {CONSTANT_REGISTER_NAME, "rdi"};
    registers->value[registers->len++] = a;
    registers->len++;
    registers->value[registers->len++] = b;
    registers->len++;
    registers->value[registers->len++] = c;
    registers->len++;
    registers->value[registers->len++] = d;
    registers->len++;
    registers->value[registers->len++] = e;
    registers->len++;
    registers->value[registers->len++] = rf;
    registers->len++;
    registers->value[registers->len++] = g;
    registers->len++;
    registers->value[registers->len++] = h;

    FILE *f = fopen(input_file, "rb");
    if (f == NULL){
        printf("Failed to open file %s\n", input_file);
        exit(1);
    };
    
    uint32_t signature;
    fread(&signature, sizeof(uint32_t), 1, f);
    if (signature != 0xCDECFACA){
        printf("Incorrect signature %u. File is not KE architecture.", signature);
        exit(1);
    };

    uint16_t minor_version;
    fread(&minor_version, sizeof(uint16_t), 1, f);


    uint16_t major_version;
    fread(&major_version, sizeof(uint16_t), 1, f);

    fread(&constant_pool_count, sizeof(unsigned int), 1, f);
    fread(&constants, sizeof(struct Constant), constant_pool_count, f);


    fread(&constant_names_count, sizeof(int), 1, f);
    fread(constant_names, sizeof(char)*50, constant_names_count, f);


    unsigned int methods_count;
    fread(&methods_count, sizeof(unsigned int), 1, f);
    fread(&methods, sizeof(struct Constant), methods_count, f);


    unsigned int instruction_count;
    fread(&instruction_count, sizeof(unsigned int), 1, f);
    fread(&instructions, sizeof(struct Instruction), instruction_count, f);



    int main_exists = 0;
    for (int i=0; i<=methods_count; i++){
        if (strcmp((char*)methods[i].bytes, "main") == 0){
            main_exists = 1;
        };
    };
    if (main_exists == 0){
        printf("Main does not exist. Please configure it");
    };

    int pass = 0;
		for (int i=0; i<=instruction_count-1; i++){
            run1(i, &pass, instruction_count);
		};
    
    fclose(f);
};

int main(int argc, char **argv){
    input_file = "<null>";
    for (int i=1; i<=argc-1; i++){
        if(strcmp(argv[i], "-h") == 0){
			help();
			exit(0);
		}else {
            input_file = argv[i];
        }
    };
    if (strcmp(input_file, "<null>") == 0){
        printf("No input file provided\n");
        help();
    } else{
        run(input_file);
    };
}