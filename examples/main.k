main {
    rdi = 57;
    rax = 60; // Exit syscall
    if 5 <= 5 {
        inc rdi
    };
    syscall;
}