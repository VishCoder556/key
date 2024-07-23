include "../libs/stdio.k"

msg: "Hello World"
msglen: $msg

main {
    rax = 6
    if rax >= 6 {
        rdi = msg
        rsi = msglen
        call print
    }
    rdi = 10
    call exit
}