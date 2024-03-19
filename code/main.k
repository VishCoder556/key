msg:"Activ8d.\n"
msglen:$msg

main {
    rax = 1 // Write syscall
    rdi = 1 // Stdout
    rsi = msg // message
    rdx = msglen // Message length
    syscall
}