include "stdio.k"

msg: "Hello World"
msglen: $msg

main {
    rdi = msg
    rsi = msglen
    call print
}