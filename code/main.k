include "stdio.k"

msg: "Hello World\n"
msglen: $msg

main {
    rsi = msg
    rdx = msglen
    call print
}