main {
    int x = 5;
    rax = 60; // Exit syscall
    rdi = x < 9;
    syscall;
}