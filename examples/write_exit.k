include "../libs/stdio.k"

msg: "Hello World"
msglen: $msg

main {
    rdi = msg
    rsi = msglen
    call _print
    rdi = 2
    inc rdi
    mul rdi, 4
    div rdi, 2
    div rdi, 3
    call exit
}