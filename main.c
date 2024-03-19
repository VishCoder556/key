#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <stdint.h>
#include "../libs/array/array.h"
#include <zlib.h>

typedef struct {
	char data[350];
	int col;
	int row;
}String;
new_arrtype(String);


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

void replaceSubstring(char *str, const char *substr, const char *replacement) {
    char *pos = strstr(str, substr); // Find the position of the substring

    if (pos != NULL) {
        int substrLen = strlen(substr);
        int replacementLen = strlen(replacement);
        int tailLen = strlen(pos + substrLen); // Length of the remaining string after the substring

        // Shift the tail of the string to make room for the replacement
        memmove(pos + replacementLen, pos + substrLen, tailLen + 1);
        
        // Copy the replacement into the position
        memcpy(pos, replacement, replacementLen);

        // Or, if you want to null-terminate the string after the replacement
        // *(pos + replacementLen + tailLen) = '\0';
    }
}

int debugMode = 0;


struct JavaClassCompiler{
	;
};

enum ConstantType{
	CONSTANT_INT,
	CONSTANT_STRING,
	CONSTANT_LEN,
	CONSTANT_METHOD,
	CONSTANT_METHOD_END
};

struct Constant{
	enum ConstantType type;
	uint8_t bytes[40];
};
char constant_names[50][50];
int constant_names_count = 0;

enum InstructionType{
    INST_JMP,
	INST_MOV,
	INST_SYSCALL,
    INST_JNZ,
    INST_INC,
    INST_ADD,
	INST_SUB,
	INST_DEC
};

struct Instruction{
	uint8_t method[10];
	enum InstructionType type;
	int col, row;
	uint8_t operand1[10];
	uint8_t operand2[10];
};

struct PersonalByteCodeCompiler {
	unsigned int constant_pool_count;
	struct Constant constant_pool[50];
	unsigned int methods_count;
	struct Constant method_pool[50];
	unsigned int instruction_count;
	struct Instruction instruction_pool[10];
};

typedef struct variable{
	char* name;
	int pos;
}variable;

new_arrtype(variable);

struct AssemblyTranspiler {
	char dataSection[1000];
	char code[9000];
	int tabs;
	int stack_size;
	arr_variable *variables;
};

struct Simulate {
	arr_string *variables;
	arr_string *registers;
	int variablelength;
};

enum TranspilerStatus  {
	Java,
	PersonalByteCode,
	Simulate,
	Normal
};

struct Transpiler { 
	enum TranspilerStatus status;
	arr_String *arr;
	char* output_file;
	char *input_file;
	char data[19999];
	int idx;
	union {
		struct JavaClassCompiler java;
		struct PersonalByteCodeCompiler personalByteCode;
		struct AssemblyTranspiler normalCompiler;
		struct Simulate simulation;
	};
};


struct Transpiler *init_transpiler(enum TranspilerStatus status, arr_String* arr, char *data, char *input_file){
	struct Transpiler *transpiler = malloc(sizeof(struct Transpiler));
	transpiler->idx = 0;
	transpiler->status = status;
	transpiler->arr = arr;
	strcpy(transpiler->data, data);
	transpiler->input_file = input_file;
	return transpiler;
};

#define create_token(str)  \
if (strcmp(arr->value[arr->len-1].data, "") == 0){strcpy(arr->value[arr->len-1].data, str);}else {strcpy(arr->value[arr->len++].data, str);}; \
		if (strcmp(arr_get(arr, arr_size(arr)-1).data, "")) { \
					strcpy(arr->value[arr->len++].data, ""); \
		} \
	mode = 3;
	
#define other() 	char *res = malloc(135); \
				strncpy(res, arr_get(arr, arr_size(arr)-1).data, 135); \
				char w[2]; \
				if (data[i] == '\\' && isalpha(data[i+1])){ \
					if (data[i+1] == 'n'){ \
						w[0] = '\n';\
					}else if (data[i+1] == 't'){ \
						w[0] = '\t';\
					};\
				}else{\
					w[0] = data[i]; \
				} \
				w[1] = '\0'; \
				if(data[i-1]=='\\'&&isalpha(data[i])){} else{ strcat(res, w); } \
				strncpy(arr->value[arr_size(arr)-1].data, res, 135);


void split(arr_String *arr, char data[300]){
	(arr->value[arr->len++].data)[0] = '\0';

	int mode = 0;


	int row = 0;
	int col = 0;

	int globalc = 0;
	for (int i=0; i<=strlen(data); i++){
		if (mode == 1){
			strncpy(arr->value[arr_size(arr)-1].data, "\"", 135);
		};
		if (mode == 1 || mode == 4){
			if (data[i] == '"'){
				mode = 0;
			}else {
				other();
				mode = 4;
			}
		}
		else if (data[i] == ' ' || data[i] == '\t' || data[i] == ','){
			if (strcmp(arr_get(arr, arr_size(arr)-1).data, "")) {
				strcpy(arr->value[arr->len++].data, "");
			}
		}else if(data[i] == '/'){
			if(data[i+1] == '/') {
				i++;
				while (data[i] != '\n'){
					i++;
				}
				col = 0;
				row++;
			}
		}
		else if(data[i] == ':'){
			create_token(":");
		}else if(data[i] == '='){
			create_token("=");
		}else if(data[i] == '('){
			create_token("(");
		}else if(data[i] == ')'){
			create_token(")");
		}else if(data[i] == '{'){
			create_token("{");
		}else if(data[i] == '}'){
			create_token("}");
		}else if(data[i] == ','){
			create_token(",");
		}else if(data[i] == '\n'){
			if (strcmp(arr_get(arr, arr_size(arr)-1).data, "")) {
				strcpy(arr->value[arr->len++].data, "");
			}
			col = 0;
			row ++;
		}else if(data[i] == '"'){
			mode = 1;
		}
		else{
			other();
		};
		col++;
		int num = arr->len-1;
		if (mode == 3){
			num = arr->len - 2;
			mode = 0;
		};
		arr_get(arr, num).col = col - strlen(arr_get(arr, num).data);
		arr_get(arr, num).row = row;
	};
	arr->len--;
};

void help(){
	printf("Manual:\n");
	printf("	-o: Specifies output file\n");
	printf("	-h: Prints this manual\n");
	printf("	-sim: Simulates the program\n");
	printf("	-byte: Compiles this program to bytecode\n");
	printf("	-class: Compiles this program to Java Virtual Machine Class File\n");
	printf("	-debug: Turns on debug mode so errors give more detail\n");
}

char *current_function;

int currentMode = 0; // Normal mode

char *transpile_expr(struct Transpiler *transpiler, char *expr);

char *transpile_phrase(struct Transpiler *transpiler, char *expr){
	if (expr[0] == '"'){
		expr++;
	};
	return expr;
};

char *transpile_expr(struct Transpiler *transpiler, char *expr){
	if(isnumber(expr[0])){
		return expr;
	};
	if (expr[0] == '$'){
		// for (int y=0; y<=strlen(transpiler->arr->value[y].data); y++){
		// 	expr[y] = expr[y+1];
		// };
		expr++;
		int a = strlen(transpile_expr(transpiler, expr));
		char data[25];
		snprintf(data, 25, "%d", a);
		expr = strdup(data);
		return expr;
	};

	for (int z=0; z<=transpiler->simulation.variables->len-1; z+=2){
		if (strcmp(arr_get(transpiler->simulation.variables, z), expr) == 0){
			// arr_get(transpiler->simulation.variables, z+1) = transpile_expr(transpiler, arr_get(transpiler->simulation.variables, z+1));
			return transpile_expr(transpiler, arr_get(transpiler->simulation.variables, z+1));
		};
	};

	for (int z=0; z<=transpiler->simulation.registers->len-1; z+=2){
		if (strcmp(arr_get(transpiler->simulation.registers, z), expr) == 0){
			return arr_get(transpiler->simulation.registers, z+1);
			// return transpile_expr(transpiler, arr_get(transpiler->simulation.registers, z+1));
		};
	};
	return transpile_phrase(transpiler, expr);
};

struct Constant transpile_expr_byte(struct Transpiler *transpiler, int i){
	struct Constant con;
	if (arr_get(transpiler->arr, i).data[0] == '$'){
		for (int y=0; y<=strlen(transpiler->arr->value[y].data); y++){
			arr_get(transpiler->arr, i).data[y] = arr_get(transpiler->arr, i).data[y+1];
		};
		con.type = CONSTANT_LEN;
		memcpy(con.bytes, arr_get(transpiler->arr, i).data, sizeof(con.bytes));
	}else if(arr_get(transpiler->arr, i).data[0] == '"'){
		con.type = CONSTANT_STRING;
		memcpy(con.bytes, arr_get(transpiler->arr, i).data, sizeof(con.bytes));
	};
	return con;
};

#define print_ln_error(extr, strt, end, showend)  \
		char *line = getNthLine(transpiler->data, transpiler->arr->value[extr].row+1); \
		char ln[50]; \ 
		sprintf(ln, "%d", transpiler->arr->value[extr].row+1); \
		for (int i=0; i<=strlen(ln); i++){ \
			printf(" "); \
		}; \
		printf("\e[0;30m|\e[0m\n", transpiler->arr->value[extr].row+1, line); \
		printf("\e[0;30m%d | \e[0m%s%s%s\n", transpiler->arr->value[extr].row+1, strt, line, end); \
		if (showend == 1) {for (int i=0; i<=strlen(ln); i++){ \
			printf(" "); \
		}; \
		printf("\e[0;30m|\e[0m", transpiler->arr->value[extr].row+1, line); \
		for (int i=0; i<=transpiler->arr->value[extr].col-1; i++){ \
			printf(" "); \
		}; \
		printf("\e[0;30m^"); \
		for (int i=1; i<=strlen(transpiler->arr->value[extr].data)-1; i++){ \
			printf("~"); \
		}; \
		printf("\e[0m\n"); }


void error(struct Transpiler *transpiler, char *info, char* type, char* i, int trace, int extr, char *extrson, char*optional){
	// printf("\033c");
	printf("\e[1;37m%s:%d:%d\e[0m: ", transpiler->output_file, transpiler->arr->value[trace].row+1, transpiler->arr->value[trace].col);
	printf("\e[0;31m%s\e[0m: \e[1;37m%s\e[0m\n", type, info);
	print_ln_error(trace, "", "", 1);
	if (strcmp(extrson, "<no extr>") == 0){}else{
	printf("\e[1;37m%s:%d:%d\e[0m: ", transpiler->output_file, transpiler->arr->value[extr].row+1, transpiler->arr->value[extr].col);
	printf("\e[0;30mnote\e[0m: %s\n", extrson);
	print_ln_error(extr, "", "", 1);
	};
	if (debugMode == 1) {
		if (strcmp(type, "RegisterError") == 0 || strcmp(type, "IncrementByStringError") == 0){
			char res[500];
			strcpy(res, i);
			replaceSubstring(res, "\n", "\\n");
			replaceSubstring(res, "\t", "\\t");
			if (strcmp(type, "IncrementByStringError") == 0) {
				printf("To fix this error, do not add by a string.\n");
				print_ln_error(trace, "\e[0;31m\e[9m", "\e[0m", 0);
				for (int i=0; i<=strlen(ln); i++){
					printf(" ");
				};
				printf("\e[0;30m|\e[0m\n", transpiler->arr->value[trace].row+1, line);
			}
		}else if(strcmp(type, "SyscallError") == 0){
			int found = 0;
			for(int i=0; i<=sizeof(syscall_list)/sizeof(syscall_list[0]); i++){
				if (syscall_list[i].number == atoi(transpiler->arr->value[extr].data)){
					found = 1;
					char *val = strdup(syscall_list[i].description);
					val[0] += 32;
					printf("Syscall #%d is %s. It can %s. However, it has not been implemented.\n", atoi(transpiler->arr->value[extr].data), syscall_list[i].name, val);
				};
			};
			if (found == 0){
				printf("Syscall %d does not exist and is an invalid syscall.\n", atoi(transpiler->arr->value[extr].data));
			};
		}else if(strcmp(type, "WriteLengthError") == 0){
			printf("\nIn order to correct the mistake, change \e[1;37mrdx\e[0m to %d.\n", strlen(optional), strlen(optional));
			print_ln_error(extr, "\e[0;31m\e[9m", "\e[0m", 0);
			char linea[50];
			strcpy(linea, line);
			char lnc[50];
			for (int j=0; j<=strlen(lnc); j++){
				lnc[j] = linea[j];
				if (linea[j] == ','){
					lnc[j+1] = '\0';
					break;
				};
			};
			strcat(lnc, " ");
			sprintf(linea, "%d", strlen(optional));
			strcat(lnc, linea);
		printf("\e[0;30m%d | \e[0;32m%s\e[0m\n", transpiler->arr->value[extr].row+1, lnc);

			for (int i=0; i<=strlen(ln); i++){
				printf(" ");
			};
			printf("\e[0;30m|\e[0m\n", transpiler->arr->value[extr].row+1, line);
		};
	}else {
		printf("-debug will give more debug information so you can fix the problem\n");
	}
	exit(1);
};

#undef print_ln_error

void transpile(struct Transpiler *transpiler, int i);

char *parse_asm(struct Transpiler *transpiler, int i){
	char *a = arr_get(transpiler->arr, i).data;
	char res[500];
	if (a[0] == '$'){
		a++;
		strcpy(res, "$ - ");
		strcat(res, a);
		return res;
	}else if(a[0] == '"'){
		strcpy(res, "db ");
		replaceSubstring(a, "\n", "\", 10, \"");
		strcat(res, a);
		strcat(res, "\"");
		return res;
	};
	strcpy(res, a);
	return res;
};

char *parse_expr_asm(struct Transpiler *transpiler, int i){
	for (int j=0; j<=transpiler->normalCompiler.stack_size-1; j++){
			// printf("{%s, %s}", arr_get(transpiler->arr, i).data, arr_get(transpiler->normalCompiler.variables, j).name);
		if (strcmp(arr_get(transpiler->arr, i).data, arr_get(transpiler->normalCompiler.variables, j).name) == 0){
			char res[50];
			sprintf(res, "%d", (transpiler->normalCompiler.stack_size-arr_get(transpiler->normalCompiler.variables, j).pos-1)*8);
			char sres[50];
			strcpy(sres, "[rsp + ");
			strcat(sres, res);
			strcat(sres, "]");
			return sres;
		};
	};
	return arr_get(transpiler->arr, i).data;
};

char rax[500];

void transpile(struct Transpiler *transpiler, int i){
	if (transpiler->status == Simulate) {
		if (strcmp(arr_get(transpiler->arr, i+1).data, ":") == 0){
			arr_push(transpiler->simulation.variables,  arr_get(transpiler->arr, i).data);
			arr_push(transpiler->simulation.variables,  arr_get(transpiler->arr, i+2).data);
		} else if (strcmp(arr_get(transpiler->arr, i+1).data, "{") == 0){
			current_function = arr_get(transpiler->arr, i).data;
		} 
		if (strcmp(arr_get(transpiler->arr, i).data, "}") == 0){
			current_function = "<global scope>";
		};
		if (strcmp(current_function, "main")==0 || (current_function[0] == '<'&&current_function[1] == 'm'&&current_function[2] == '>')) {
			if (strcmp(arr_get(transpiler->arr, i+1).data, "=") == 0){
				char *val = arr_get(transpiler->arr, i).data;
				// if (strcmp(arr_get(transpiler->arr, i).data, "") == 0){
				// 	val = arr_get(transpiler->arr, i-1).data;
				// };
				for (int y=0; y<=transpiler->simulation.registers->len-1; y+=2){
					if (strcmp(val, arr_get(transpiler->simulation.registers, y)) == 0){
						arr_get(transpiler->simulation.registers, y+1) = transpile_expr(transpiler, arr_get(transpiler->arr, i+2).data);
					};
				};
			}else if (strcmp(arr_get(transpiler->arr, i).data, "inc") == 0){
				char *val = arr_get(transpiler->arr, i+1).data;
				for (int y=0; y<=transpiler->simulation.registers->len-1; y+=2){
					if (strcmp(val, arr_get(transpiler->simulation.registers, y)) == 0){
						if (isalpha(arr_get(transpiler->simulation.registers, y+1)[0])){
							sprintf(arr_get(transpiler->simulation.registers, y+1), "%s", arr_get(transpiler->simulation.registers, y+1)+1);
						}else {
							sprintf(arr_get(transpiler->simulation.registers, y+1), "%d", atoi(arr_get(transpiler->simulation.registers, y+1))+1);
						}
					};
				};
			}else if (strcmp(arr_get(transpiler->arr, i).data, "dec") == 0){
				char *val = arr_get(transpiler->arr, i+1).data;
				for (int y=0; y<=transpiler->simulation.registers->len-1; y+=2){
					if (strcmp(val, arr_get(transpiler->simulation.registers, y)) == 0){
						if (isalpha(arr_get(transpiler->simulation.registers, y+1)[0])){
							sprintf(arr_get(transpiler->simulation.registers, y+1), "%s", arr_get(transpiler->simulation.registers, y+1)-1);
						}else {
							sprintf(arr_get(transpiler->simulation.registers, y+1), "%d", atoi(arr_get(transpiler->simulation.registers, y+1))-1);
						}
					};
				};
			}else if (strcmp(arr_get(transpiler->arr, i).data, "add") == 0){
				char *val = arr_get(transpiler->arr, i+1).data;
				for (int y=0; y<=transpiler->simulation.registers->len-1; y+=2){
					if (strcmp(val, arr_get(transpiler->simulation.registers, y)) == 0){
						// printf("{%s}", arr_get(transpiler->arr, i+2).data);
						if (isalpha(arr_get(transpiler->simulation.registers, y+1)[0])){
							sprintf(arr_get(transpiler->simulation.registers, y+1), "%s", arr_get(transpiler->simulation.registers, y+1)+atoi(transpile_expr(transpiler, arr_get(transpiler->arr, i+2).data)));
						}else if (isalpha(transpile_expr(transpiler, arr_get(transpiler->arr, i+2).data)[0])){
							int global = 0;
							for (int i=0; i<=transpiler->arr->len-1; i++){
								if ((strcmp(arr_get(transpiler->arr, i+1).data, "=") == 0 || strcmp(arr_get(transpiler->arr, i+2).data, "=") == 0) && strcmp(arr_get(transpiler->arr, i).data, arr_get(transpiler->simulation.registers, y)) == 0){
									global = i;
								};
							};
							error(transpiler, "Cannot add by string while in Simulation mode. That feature only works in Bytecode mode", "IncrementByStringError", arr_get(transpiler->simulation.registers, y+1), i+2, global+2, "The types of the two do not match as you can see", "");
						}else {
							sprintf(arr_get(transpiler->simulation.registers, y+1), "%d", atoi(arr_get(transpiler->simulation.registers, y+1))+atoi(transpile_expr(transpiler, arr_get(transpiler->arr, i+2).data)));
						}
					};
				};
			}else if (strcmp(arr_get(transpiler->arr, i).data, "sub") == 0){
				char *val = arr_get(transpiler->arr, i+1).data;
				for (int y=0; y<=transpiler->simulation.registers->len-1; y+=2){
					if (strcmp(val, arr_get(transpiler->simulation.registers, y)) == 0){
						// printf("{%s}", arr_get(transpiler->arr, i+2).data);
						if (isalpha(arr_get(transpiler->simulation.registers, y+1)[0])){
							sprintf(arr_get(transpiler->simulation.registers, y+1), "%s", arr_get(transpiler->simulation.registers, y+1)-atoi(transpile_expr(transpiler, arr_get(transpiler->arr, i+2).data)));
						}else if (isalpha(transpile_expr(transpiler, arr_get(transpiler->arr, i+2).data)[0])){
							int global = 0;
							for (int i=0; i<=transpiler->arr->len-1; i++){
								if ((strcmp(arr_get(transpiler->arr, i+1).data, "=") == 0 || strcmp(arr_get(transpiler->arr, i+2).data, "=") == 0) && strcmp(arr_get(transpiler->arr, i).data, arr_get(transpiler->simulation.registers, y)) == 0){
									global = i;
								};
							};
							error(transpiler, "Cannot subtract by string while in Simulation mode. That feature only works in Bytecode mode", "IncrementByStringError", arr_get(transpiler->simulation.registers, y+1), i+2, global+2, "The types of the two do not match as you can see", "");
						}else {
							sprintf(arr_get(transpiler->simulation.registers, y+1), "%d", atoi(arr_get(transpiler->simulation.registers, y+1))-atoi(transpile_expr(transpiler, arr_get(transpiler->arr, i+2).data)));
						}
					};
				};
			} else if (strcmp(arr_get(transpiler->arr, i).data, "syscall") == 0){
				char *rax = arr_get(transpiler->simulation.registers, 1);
				char *rdi = arr_get(transpiler->simulation.registers, 15);
				char *rsi = transpile_phrase(transpiler, arr_get(transpiler->simulation.registers, 13));
				char *rdx = arr_get(transpiler->simulation.registers, 7);
				if (atoi(rax) == 0) {
					char *buf;
					read(atoi(rdi), buf, atoi(rdx));
					sprintf(arr_get(transpiler->simulation.registers, 1), "%s", buf);
				}else if (atoi(rax) == 1) {
					if (atoi(rdx) > strlen(rsi)){

							int global = 0;
							for (int i=0; i<=transpiler->arr->len-1; i++){
								if ((strcmp(arr_get(transpiler->arr, i+1).data, "=") == 0 || strcmp(arr_get(transpiler->arr, i+2).data, "=") == 0) && strcmp(arr_get(transpiler->arr, i).data, "rdx") == 0){
									global = i;
								};
							};

						char err[500];
						sprintf(err, "Number of characters to print higher than length of message.", atoi(rax));
						error(transpiler, err, "WriteLengthError", "syscall", i, global, "This is where the length was set", rsi);
						exit(1);
					};
					write(atoi(rdi), rsi, atoi(rdx));
				}else if (atoi(rax) == 2) {
					sprintf(arr_get(transpiler->simulation.registers, 1), "%d", open(rdi, O_RDWR | O_CREAT));
				}else if (atoi(rax) == 3) {
					close(atoi(rdi));
				}else if(atoi(rax) == 60){
					exit(atoi(rdi));
				}else {
					char err[500];
							int global = 0;
							for (int i=0; i<=transpiler->arr->len-1; i++){
								if ((strcmp(arr_get(transpiler->arr, i+1).data, "=") == 0 || strcmp(arr_get(transpiler->arr, i+2).data, "=") == 0) && strcmp(arr_get(transpiler->arr, i).data, "rax") == 0){
									global = i;
									if(strcmp(arr_get(transpiler->arr, i+2).data, "=") == 0){
										global++;
									};
								};
							};

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
					error(transpiler, err, "SyscallError", "syscall", i, global+2, "invalid syscall number was set here", "");
				}
			}else if(strcmp(arr_get(transpiler->arr, i).data, "jmp") == 0){
				char crf[50];
				strcpy(crf, "<m>");
				strcat(crf, arr_get(transpiler->arr, i+1).data);
				current_function = strdup(crf);
				for (int j=0; j<=transpiler->arr->len; j++){
					if (j == i){
						j+=2;
					};
					if (strcmp(arr_get(transpiler->arr, j).data, arr_get(transpiler->arr, i+1).data) == 0 && strcmp(arr_get(transpiler->arr, j+2).data, "{") == 0){
						j+=3;
						while (strcmp(arr_get(transpiler->arr, j).data, "}")){
							transpile(transpiler, j);
							j++;
						}
					};
				};
			}else if(strcmp(arr_get(transpiler->arr, i).data, "jnz") == 0){
				if (atoi(arr_get(transpiler->simulation.registers, 1))==0){
					i+=2;
					return;
				};
				char crf[50];
				strcpy(crf, "<m>");
				strcat(crf, arr_get(transpiler->arr, i+1).data);
				current_function = strdup(crf);
				// arr_get(transpiler->arr, i+1).data;
				for (int j=0; j<=transpiler->arr->len; j++){
					if (j == i){
						j+=2;
					};
					// printf("[%s], [%s]\n", arr_get(transpiler->arr, j).data, arr_get(transpiler->arr, i+1).data);
					if (strcmp(arr_get(transpiler->arr, j).data, arr_get(transpiler->arr, i+1).data) == 0 && strcmp(arr_get(transpiler->arr, j+1).data, "{") == 0){
						j++;
						while (strcmp(arr_get(transpiler->arr, j).data, "}")){
							transpile(transpiler, j);
							j++;
						}
					};
				};
			}
		}
	}else if(transpiler->status == PersonalByteCode){
		if (strcmp(arr_get(transpiler->arr, i+1).data, ":") == 0){
			i+=2;
			transpiler->personalByteCode.constant_pool[transpiler->personalByteCode.constant_pool_count++] = transpile_expr_byte(transpiler, i);
			strcpy(constant_names[constant_names_count++], arr_get(transpiler->arr, i-2).data);
			i++;
		}else if (strcmp(arr_get(transpiler->arr, i+1).data, "{") == 0){
			current_function = arr_get(transpiler->arr, i).data;
			if (strcmp(current_function, "") == 0){
				current_function = arr_get(transpiler->arr, i-1).data;
			};
		} else if (strcmp(arr_get(transpiler->arr, i).data, "}") == 0){
			transpiler->personalByteCode.method_pool[transpiler->personalByteCode.methods_count].type = CONSTANT_METHOD;
			int byteslen = sizeof(transpiler->personalByteCode.method_pool[transpiler->personalByteCode.methods_count].bytes);
			memcpy(transpiler->personalByteCode.method_pool[transpiler->personalByteCode.methods_count].bytes, current_function, byteslen);
			transpiler->personalByteCode.methods_count++;
			current_function = "<global scope>";
		}else if(strcmp(arr_get(transpiler->arr, i).data, "syscall") == 0){
			int byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method, current_function, byteslen);
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].type = INST_SYSCALL;
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].col = arr_get(transpiler->arr, i).col;
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].row = arr_get(transpiler->arr, i).row;
			transpiler->personalByteCode.instruction_count++;
		}else if(strcmp(arr_get(transpiler->arr, i+1).data, "=") == 0){

			char *val = arr_get(transpiler->arr, i).data;
			if (strcmp(arr_get(transpiler->arr, i).data, "") == 0){
				val = arr_get(transpiler->arr, i-1).data;
			};

			int byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method, current_function, byteslen);
			

			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].type = INST_MOV;

			byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand1);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand1, val, byteslen);


			byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand2);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand2, arr_get(transpiler->arr, i+2).data, byteslen);
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].col = arr_get(transpiler->arr, i).col;
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].row = arr_get(transpiler->arr, i).row;
			transpiler->personalByteCode.instruction_count++;
		}else if(strcmp(arr_get(transpiler->arr, i).data, "add") == 0){
			int byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method, current_function, byteslen);
			

			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].type = INST_ADD;

			byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand1);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand1, arr_get(transpiler->arr, i+1).data, byteslen);


			byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand2);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand2, arr_get(transpiler->arr, i+2).data, byteslen);
			
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].col = arr_get(transpiler->arr, i).col;
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].row = arr_get(transpiler->arr, i).row;
			transpiler->personalByteCode.instruction_count++;
		}else if(strcmp(arr_get(transpiler->arr, i).data, "sub") == 0){
			int byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method, current_function, byteslen);
			

			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].type = INST_SUB;

			byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand1);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand1, arr_get(transpiler->arr, i+1).data, byteslen);


			byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand2);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand2, arr_get(transpiler->arr, i+2).data, byteslen);
			
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].col = arr_get(transpiler->arr, i).col;
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].row = arr_get(transpiler->arr, i).row;
			transpiler->personalByteCode.instruction_count++;
		}else if (strcmp(arr_get(transpiler->arr, i).data, "inc") == 0){
			int byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method, current_function, byteslen);
			

			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].type = INST_INC;

			byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand1);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand1, arr_get(transpiler->arr, i+1).data, byteslen);
			
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].col = arr_get(transpiler->arr, i).col;
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].row = arr_get(transpiler->arr, i).row;
			transpiler->personalByteCode.instruction_count++;
		}else if (strcmp(arr_get(transpiler->arr, i).data, "dec") == 0){
			int byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method, current_function, byteslen);
			

			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].type = INST_DEC;

			byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand1);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand1, arr_get(transpiler->arr, i+1).data, byteslen);
			
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].col = arr_get(transpiler->arr, i).col;
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].row = arr_get(transpiler->arr, i).row;
			transpiler->personalByteCode.instruction_count++;
		}else if(strcmp(arr_get(transpiler->arr, i).data, "jmp") == 0){
			int byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method, current_function, byteslen);
			

			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].type = INST_JMP;

			byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand1);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand1, arr_get(transpiler->arr, i+1).data, byteslen);
			
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].col = arr_get(transpiler->arr, i).col;
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].row = arr_get(transpiler->arr, i).row;
			transpiler->personalByteCode.instruction_count++;
		}else if(strcmp(arr_get(transpiler->arr, i).data, "jnz") == 0){
			int byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].method, current_function, byteslen);
			

			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].type = INST_JNZ;

			byteslen = sizeof(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand1);
			memcpy(transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].operand1, arr_get(transpiler->arr, i+1).data, byteslen);
			
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].col = arr_get(transpiler->arr, i).col;
			transpiler->personalByteCode.instruction_pool[transpiler->personalByteCode.instruction_count].row = arr_get(transpiler->arr, i).row;
			transpiler->personalByteCode.instruction_count++;
		}
	}else if(transpiler->status == Normal){
		if (strcmp(arr_get(transpiler->arr, i+1).data, ":") == 0){
			strcat(transpiler->normalCompiler.dataSection, "\t");
			strcat(transpiler->normalCompiler.dataSection, arr_get(transpiler->arr, i).data);
			if (arr_get(transpiler->arr, i+2).data[0] == '\"') {
				strcat(transpiler->normalCompiler.dataSection, ": ");
			}else {
				strcat(transpiler->normalCompiler.dataSection, " equ ");
			}
			strcat(transpiler->normalCompiler.dataSection, parse_asm(transpiler, i+2));
			strcat(transpiler->normalCompiler.dataSection, "\n");
		}else if(strcmp(arr_get(transpiler->arr, i+1).data, "{") == 0){
			char *wdata = arr_get(transpiler->arr, i).data;
			if (strcmp(wdata, "") == 0){
				wdata = arr_get(transpiler->arr, i-1).data;
			};
			strcat(transpiler->normalCompiler.code, wdata);
			strcat(transpiler->normalCompiler.code, ":\n");
	   		transpiler->normalCompiler.tabs++;
			i++;
		}else if(strcmp(arr_get(transpiler->arr, i).data, "}") == 0){
			for (int i=0; i<transpiler->normalCompiler.tabs; i++){
				strcat(transpiler->normalCompiler.code, "\t");
			};
			strcat(transpiler->normalCompiler.code, "ret\n");
	   		transpiler->normalCompiler.tabs--;
		}else if(strcmp(arr_get(transpiler->arr, i+1).data, "=") == 0){
			for (int i=0; i<transpiler->normalCompiler.tabs; i++){
				strcat(transpiler->normalCompiler.code, "\t");
			};
			char *val = arr_get(transpiler->arr, i).data;
			if (strcmp(arr_get(transpiler->arr, i).data, "") == 0){
				val = arr_get(transpiler->arr, i-1).data;
			};
			if (strcmp(val, "rax") == 0){
				strcpy(rax, parse_asm(transpiler, i+2));
			};
			if (strcmp(val, "rax") && strcmp(val, "rbx") && strcmp(val, "rcx") && strcmp(val, "rdx") && strcmp(val, "rsp") && strcmp(val, "rbp") && strcmp(val, "rsi") && strcmp(val, "rdi") && strcmp(val, "r10") && strcmp(val, "r11") && strcmp(val, "r12") && strcmp(val, "r13") && strcmp(val, "r14")){
				strcat(transpiler->normalCompiler.code, "mov r15, ");
				strcat(transpiler->normalCompiler.code, arr_get(transpiler->arr, i+2).data);
				strcat(transpiler->normalCompiler.code, "\n");
				for (int i=0; i<transpiler->normalCompiler.tabs; i++){
					strcat(transpiler->normalCompiler.code, "\t");
				};
				strcat(transpiler->normalCompiler.code, "push r15\n");
				transpiler->normalCompiler.variables->value[transpiler->normalCompiler.variables->len].name = val;
				transpiler->normalCompiler.variables->value[transpiler->normalCompiler.variables->len++].pos = transpiler->normalCompiler.stack_size;
				transpiler->normalCompiler.stack_size++;
			}else {
				strcat(transpiler->normalCompiler.code, "mov ");
				strcat(transpiler->normalCompiler.code, val);
				strcat(transpiler->normalCompiler.code, ", ");
				strcat(transpiler->normalCompiler.code, parse_expr_asm(transpiler, i+2));
				strcat(transpiler->normalCompiler.code, "\n");
			}

		}else if(strcmp(arr_get(transpiler->arr, i).data, "syscall") == 0){
			if (strcmp(rax, "1") == 0){
				for (int i=0; i<transpiler->normalCompiler.tabs; i++){
					strcat(transpiler->normalCompiler.code, "\t");
				};
				strcat(transpiler->normalCompiler.code, "mov rax, 0x02000004");
				strcat(transpiler->normalCompiler.code, "\n");
			}else if (strcmp(rax, "60") == 0){
				for (int i=0; i<transpiler->normalCompiler.tabs; i++){
					strcat(transpiler->normalCompiler.code, "\t");
				};
				strcat(transpiler->normalCompiler.code, "mov rax, 0x02000001");
				strcat(transpiler->normalCompiler.code, "\n");
			};
			for (int i=0; i<transpiler->normalCompiler.tabs; i++){
				strcat(transpiler->normalCompiler.code, "\t");
			};
			strcat(transpiler->normalCompiler.code, "syscall");
			strcat(transpiler->normalCompiler.code, "\n");
		}else if(strcmp(arr_get(transpiler->arr, i).data, "jmp") == 0){
			for (int i=0; i<transpiler->normalCompiler.tabs; i++){
				strcat(transpiler->normalCompiler.code, "\t");
			};
			strcat(transpiler->normalCompiler.code, "jmp ");
			strcat(transpiler->normalCompiler.code, arr_get(transpiler->arr, i+1).data);
			strcat(transpiler->normalCompiler.code, "\n");
		}else if(strcmp(arr_get(transpiler->arr, i).data, "jnz") == 0){
			for (int i=0; i<transpiler->normalCompiler.tabs; i++){
				strcat(transpiler->normalCompiler.code, "\t");
			};
			strcat(transpiler->normalCompiler.code, "test rax, rax\n");
			for (int i=0; i<transpiler->normalCompiler.tabs; i++){
				strcat(transpiler->normalCompiler.code, "\t");
			};
			strcat(transpiler->normalCompiler.code, "jnz ");
			strcat(transpiler->normalCompiler.code, arr_get(transpiler->arr, i+1).data);
			strcat(transpiler->normalCompiler.code, "\n");
		}else if(strcmp(arr_get(transpiler->arr, i).data, "inc") == 0){
			for (int i=0; i<transpiler->normalCompiler.tabs; i++){
				strcat(transpiler->normalCompiler.code, "\t");
			};
			strcat(transpiler->normalCompiler.code, "inc ");
			if (strcmp(arr_get(transpiler->arr, i+1).data, "rax") == 0){
				char d[500];
				sprintf(d, "%d", atoi(rax)+1);
				strcpy(rax, d);
			};
			strcat(transpiler->normalCompiler.code, arr_get(transpiler->arr, i+1).data);
			strcat(transpiler->normalCompiler.code, "\n");
	   		transpiler->normalCompiler.tabs--;
		}else if(strcmp(arr_get(transpiler->arr, i).data, "dec") == 0){
			for (int i=0; i<transpiler->normalCompiler.tabs; i++){
				strcat(transpiler->normalCompiler.code, "\t");
			};
			strcat(transpiler->normalCompiler.code, "dec ");
			if (strcmp(arr_get(transpiler->arr, i+1).data, "rax") == 0){
				char d[500];
				sprintf(d, "%d", atoi(rax)-1);
				strcpy(rax, d);
			};
			strcat(transpiler->normalCompiler.code, arr_get(transpiler->arr, i+1).data);
			strcat(transpiler->normalCompiler.code, "\n");
	   		transpiler->normalCompiler.tabs--;
		}else if(strcmp(arr_get(transpiler->arr, i).data, "add") == 0){
			char *a = arr_get(transpiler->arr, i+2).data;
			for (int i=0; i<transpiler->normalCompiler.tabs; i++){
				strcat(transpiler->normalCompiler.code, "\t");
			};
			strcat(transpiler->normalCompiler.code, "add ");
			if (strcmp(arr_get(transpiler->arr, i+1).data, "rax") == 0){
				char d[500];
				sprintf(d, "%d", atoi(rax)+atoi(a));
				strcpy(rax, d);
			};
			strcat(transpiler->normalCompiler.code, arr_get(transpiler->arr, i+1).data);
			strcat(transpiler->normalCompiler.code, ", ");
			strcat(transpiler->normalCompiler.code, arr_get(transpiler->arr, i+2).data);
			strcat(transpiler->normalCompiler.code, "\n");
	   		transpiler->normalCompiler.tabs--;
		}else if(strcmp(arr_get(transpiler->arr, i).data, "sub") == 0){
			char *a = arr_get(transpiler->arr, i+2).data;
			for (int i=0; i<transpiler->normalCompiler.tabs; i++){
				strcat(transpiler->normalCompiler.code, "\t");
			};
			strcat(transpiler->normalCompiler.code, "sub ");
			if (strcmp(arr_get(transpiler->arr, i+1).data, "rax") == 0){
				char d[500];
				sprintf(d, "%d", atoi(rax)-atoi(a));
				strcpy(rax, d);
			};
			strcat(transpiler->normalCompiler.code, arr_get(transpiler->arr, i+1).data);
			strcat(transpiler->normalCompiler.code, ", ");
			strcat(transpiler->normalCompiler.code, arr_get(transpiler->arr, i+2).data);
			strcat(transpiler->normalCompiler.code, "\n");
	   		transpiler->normalCompiler.tabs--;
		}
	};
};

void run_transpiler(struct Transpiler *transpiler){
	current_function = "<global scope>";
	if (transpiler->status == Simulate){
		transpiler->simulation.variables = arr_new(string);
		transpiler->simulation.registers = arr_new(string);
		arr_push(transpiler->simulation.registers, "rax");
		arr_push(transpiler->simulation.registers, "");
		arr_push(transpiler->simulation.registers, "rbx");
		arr_push(transpiler->simulation.registers, "");
		arr_push(transpiler->simulation.registers, "rcx");
		arr_push(transpiler->simulation.registers, "");
		arr_push(transpiler->simulation.registers, "rdx");
		arr_push(transpiler->simulation.registers, "");
		arr_push(transpiler->simulation.registers, "rsp");
		arr_push(transpiler->simulation.registers, "");
		arr_push(transpiler->simulation.registers, "rbp");
		arr_push(transpiler->simulation.registers, "");
		arr_push(transpiler->simulation.registers, "rsi");
		arr_push(transpiler->simulation.registers, "");
		arr_push(transpiler->simulation.registers, "rdi");
		arr_push(transpiler->simulation.registers, "");
		arr_push(transpiler->simulation.registers, "r10");
		arr_push(transpiler->simulation.registers, "");
		arr_push(transpiler->simulation.registers, "r11");
		arr_push(transpiler->simulation.registers, "");
		arr_push(transpiler->simulation.registers, "r12");
		arr_push(transpiler->simulation.registers, "");
		arr_push(transpiler->simulation.registers, "r13");
		arr_push(transpiler->simulation.registers, "");
		arr_push(transpiler->simulation.registers, "r14");
		transpiler->simulation.variablelength = 0;
		for (int i=0; i<=transpiler->arr->len; i++){
			transpile(transpiler, i);
		};
	}else if(transpiler->status == PersonalByteCode) {
       FILE *f  = fopen(transpiler->output_file, "wb");
	   if (f == 0){
         printf("No permissions to write into bytecode file %s\n", transpiler->output_file);
	   };
	   uint32_t magic = 0xCDECFACA;
	   uint16_t minor_version = 0x0000;
	   uint16_t major_version = 0x0000;
	   fwrite(&magic, 1, sizeof(uint32_t), f);
	   fwrite(&minor_version, 1, sizeof(uint16_t), f);
	   fwrite(&major_version, 1, sizeof(uint16_t), f);
	   transpiler->personalByteCode.constant_pool_count = 0;
	   transpiler->personalByteCode.methods_count = 0;
	   transpiler->personalByteCode.instruction_count = 0;
		for (int i=0; i<=transpiler->arr->len; i++){
			transpile(transpiler, i);
		};
		fwrite(&transpiler->personalByteCode.constant_pool_count, sizeof(unsigned int), 1, f);
		fwrite(&transpiler->personalByteCode.constant_pool, sizeof(struct Constant), transpiler->personalByteCode.constant_pool_count, f);
		fwrite(&constant_names_count, sizeof(int), 1, f);
		fwrite(constant_names, sizeof(char)*50, constant_names_count, f);
		fwrite(&transpiler->personalByteCode.methods_count, sizeof(unsigned int), 1, f);
		fwrite(&transpiler->personalByteCode.method_pool, sizeof(struct Constant), transpiler->personalByteCode.methods_count, f);
		fwrite(&transpiler->personalByteCode.instruction_count, sizeof(unsigned int), 1, f);
		fwrite(&transpiler->personalByteCode.instruction_pool, sizeof(struct Instruction), transpiler->personalByteCode.instruction_count, f);
	   fclose(f);
	}else if(transpiler->status == Normal){
		transpiler->normalCompiler.variables = arr_new(variable);
		transpiler->normalCompiler.stack_size = 0;
		strcpy(rax, "");

    struct stat st;
    mode_t orig_mode;


    char *original_content;

    int statn = stat(transpiler->output_file, &st);

	
    struct stat st2;
    mode_t orig_mode2;


    char *original_content2;

    int statn2 = stat("main.o", &st2);

    if (statn != -1)  {
        original_content = malloc(st.st_size + 1);
        if (original_content == NULL) {
            perror("Error allocating memory");
            exit(1);
        }

        int fd = open(transpiler->output_file, O_RDONLY);
        if (fd == -1) {
            perror("Error opening file for reading");
            free(original_content);
            exit(1);
        }

        ssize_t bytes_read = read(fd, original_content, st.st_size);
        if (bytes_read == -1) {
            perror("Error reading file");
            free(original_content);
            close(fd);
            exit(1);
        }
        original_content[st.st_size] = '\0';
        close(fd);
        orig_mode = st.st_mode;
    }

       FILE *f  = fopen(transpiler->output_file, "w");
	   if (f == 0){
         fprintf(stderr, "No permissions to write into assembly file %s\n", transpiler->output_file);
	   };
	   char *str = "global start\n";
	   fwrite(str, sizeof(char), strlen(str), f);
	   transpiler->normalCompiler.tabs = 0;


		for (int i=0; i<=transpiler->arr->len; i++){
			transpile(transpiler, i);
		};

		str = "section .data\n";
	   fwrite(str, sizeof(char), strlen(str), f);
	   fwrite(transpiler->normalCompiler.dataSection, sizeof(char), strlen(transpiler->normalCompiler.dataSection), f);
		str = "section .text\n";
	   fwrite(str, sizeof(char), strlen(str), f);
	   fwrite(transpiler->normalCompiler.code, sizeof(char), strlen(transpiler->normalCompiler.code), f);
	   str = "start:\n\tcall main\n\tmov       rax, 0x02000001\n\tmov       rdi, 0\n\tsyscall\n\tret";
	   fwrite(str, sizeof(char), strlen(str), f);

	   fclose(f);

		char res[500];

		if (statn2 != -1)  {
			original_content2 = malloc(st2.st_size + 1);
			if (original_content2 == NULL) {
				perror("Error allocating memory");
				exit(1);
			}

			int fd = open("main.o", O_RDONLY);
			if (fd == -1) {
				perror("Error opening file for reading");
				free(original_content2);
				exit(1);
			}

			ssize_t bytes_read = read(fd, original_content2, st.st_size);
			if (bytes_read == -1) {
				perror("Error reading file");
				free(original_content2);
				close(fd);
				exit(1);
			}
			original_content2[st.st_size] = '\0';
			close(fd);
			orig_mode2 = st.st_mode;
		}
		sprintf(res, "nasm -f macho64 %s -o main.o", transpiler->output_file);
		system(res);
		system("ld -macosx_version_min 10.13 -o main main.o -static");

		if (statn2 == -1){

			if (unlink("main.o") == -1) {
				perror("Error deleting file");
            	exit(1);
			}
		}else {

			FILE *f = fopen("main.o", "w");
			if (f == 0){
				printf("Failed to revert to original content.\n");
				free(original_content2);
            	exit(1);
			};
			fwrite(original_content2, sizeof(char), strlen(original_content2), f);
			fclose(f);
			if (chmod("main.o", orig_mode2) == -1) {
				perror("Error reverting file permissions");
				printf("Failed to revert file permissions.\n");
				free(original_content2);
            	exit(1);
			}
			free(original_content2);
		}

		if (statn == -1){

			if (unlink(transpiler->output_file) == -1) {
				perror("Error deleting file");
            	exit(1);
			}
		}else {

			FILE *f = fopen(transpiler->output_file, "w");
			if (f == 0){
				printf("Failed to revert to original content.\n");
				free(original_content);
            	exit(1);
			};
			fwrite(original_content, sizeof(char), strlen(original_content), f);
			fclose(f);
			if (chmod(transpiler->output_file, orig_mode) == -1) {
				perror("Error reverting file permissions");
				printf("Failed to revert file permissions.\n");
				free(original_content);
            	exit(1);
			}
			free(original_content);
		}
	}
};

int main(int argc, char **argv){
	char *input_file = "main.k";
	char *output_file;
	enum TranspilerStatus mode = Normal;
	for (int i=0; i<=argc-1; i++){
		if (*argv == 0){
			argv++;
			continue;
		};
		if (strcmp(*argv, "-o") == 0){
			argv++;
			output_file = *argv;
		} else if(strcmp(*argv, "-h") == 0){
			help();
			exit(0);
		} else if(strcmp(*argv, "-sim") == 0){
			mode = Simulate;
		}else if(strcmp(*argv, "-byte") == 0){
			mode = PersonalByteCode;
		}else if(strcmp(*argv, "-class") == 0){
			mode = Java;
		}else if(strcmp(*argv, "-debug") == 0){
			debugMode = 1;
		} else if(strcmp(*argv, "-h") == 0){
			exit(0);
		} else if(*argv[0] == '-'){
			printf("Unexpected Instruction %s\n", *argv);
			help();
			exit(1);
		} else {
			input_file = *argv;
		}
		argv++;
	};
	if (argc == 1){
		printf("Problem: no input files\n");
		help();
		exit(1);
	};
	if (output_file == 0) {
		output_file = "main.s";
		if (mode == PersonalByteCode) {
          output_file = "a.ke";
		};
	};
	FILE *f = fopen(input_file, "r");
	if (f == 0){
		fprintf(stderr, "The file %s does not exist.\n", input_file);
		exit(1);
	};
	char data[900000];
	fread(data, sizeof(char)*900000, 1, f);
	fclose(f);
	arr_String *arr = arr_new(String);
	for (int i=0; i<=250; i++){
		memcpy(&arr->value[i], malloc(sizeof(String)), sizeof(String));
		memcpy(arr->value[i].data, malloc(360), 360);
		arr->value[i].col = 0;
		arr->value[i].row = 0;
	};
	split(arr, data);
	struct Transpiler *transpiler = init_transpiler(mode, arr, data, input_file);
	transpiler->output_file = output_file;
	run_transpiler(transpiler);
	arr_destroy(arr);
	return 0;
}
