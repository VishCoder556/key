exit {
    rax = 60;
    syscall;
}

fprintf {
    rax = 1;
    syscall;
}

newline: "\n"

write {
    rdi = 1;
    syscall;
}

print {
    rdx = rsi;
    rsi = rdi;
    rax = 1;
    call write;
    rsi = newline;
    rdx = 1;
    call write;
}

open {
    rax = 2;
    syscall;
}

close {
    rax = 3;
    syscall;
}