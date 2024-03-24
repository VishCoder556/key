exit {
    rax = 60;
    syscall;
}

fprintf {
    rax = 1;
    syscall;
}

print {
    rax = 1;
    rdi = 1;
    syscall;
}

open {
    rax = 2;
    syscall;
}

close {
    rax = 3;
    syscall;
}