include "../libs/stdio.k"

msg: "Hello Worlds"

main {
    rdi = msg
    call print
    rdi = 10
    call exit;
}