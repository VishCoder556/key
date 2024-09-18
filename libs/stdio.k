exit {
    // takes in rdi as return value
    rax = 60;
    syscall;
}

fprintf {
    // takes in rdi = fd, rsi = string, rdx = length
    rax = 1;
    syscall;
}

newline: "\n"

write {
    // takes in rdi = fd, rsi = string, rdx = length
    rdi = 1;
    syscall;
}

_print {
    // takes in rsi = length, rdi = string
    rdx = rsi;
    rsi = rdi;
    rax = 1;
    call write;
    rsi = newline;
    rdx = 1;
    call write;
}

print {
    // takes in rdi = string
    rsi = rdi
    call strlen
    call _print
}

println {
    // takes in rdi = string
    rsi = rdi
    call strlen
    call _print
    rsi = 1
    rdi = newline
    call _print
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