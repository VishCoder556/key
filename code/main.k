include "stdio.k"

msg: 'Hello World\n'
msglen: $msg

main {
    char a = 25383;
    rsi = a
    rdx = msglen
    call print
}