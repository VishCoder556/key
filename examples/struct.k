include "../libs/stdio.k"

struct Man {
    int member;
}

main {
    struct Man a = 10;
    a.member = 8;
    rdi = a.member;
    inc rdi;
    call exit;
}