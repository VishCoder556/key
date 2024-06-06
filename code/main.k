include stdio

msg: "Hello World\n"
msglen: $msg

main {
    rdi = msg
    rsi = msglen
    call print
}