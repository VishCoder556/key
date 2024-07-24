include "../libs/stdio.k"

ptr a = mem 1;

main {
    a = 8
    rdi = a
    call exit
}