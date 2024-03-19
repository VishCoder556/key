msg:"I was here."
msglen:$msg
fn:"hello"

main {
    rax = 2 // Open syscall
    rdi = fn // File name
    syscall

    rdi = rax // File descriptor
    rax = 1 // Write syscall
    rsi = msg // message
    rdx = msglen // Message length
    syscall


    rax = 3 // Close syscall
    syscall
}