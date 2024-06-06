exit {
    // takes in rdi as return value
    rax = 60;
    syscall;
}

fprintf {
    // takes in rdi = fd, rsi = string, rdi = length
    rax = 1;
    syscall;
}

newline: "\n"

write {
    // takes in rdi = fd, rsi = string, rdi = length
    rdi = 1;
    syscall;
}

print {
    // takes in rsi = length, rdi = string
    rdx = rsi;
    rsi = rdi;
    rax = 1;
    call write;
    rsi = newline;
    rdx = 1;
    call write;
}


open {
    // takes in rdi = file, rsi = flags, rdx = mode
    rax = 2;
    syscall;
}

close {
    // takes in rdi = fd
    rax = 3;
    syscall;
}