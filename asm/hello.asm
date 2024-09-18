global start

section .data
	msg: db  "Hello World", 10
	msglen equ  $ - msg
section .text
start:
    mov rdx, msglen
    mov rsi, msg
	mov rdi, 1
	mov rax, 0x02000004
	syscall
    mov rax, 0x02000001
	mov       rdi, 0
	syscall
	ret