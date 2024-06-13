include "../libs/stdio.k"

msg: "Hello World"
msglen: $msg

struct

main {
    rdi = msg
    rsi = msglen
    call print
    rdi = 5
    call exit
}