include stdio

msg: "Hello World"
msglen: $msg

main {
    rdi = msg
    rsi = msglen
    call print
    rdi = 2
    inc rdi
    mul rdi, 4
    div rdi, 2
    div rdi, 3
    call exit
}