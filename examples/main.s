global start

section .data
	__w: dw 0
	newline: db  "", 10, ""
	msg: db  "Hello World"
	msglen equ  $ - msg
section .text
exit:
	mov r13, 60
	mov rax, r13
	mov rax, 0x02000001
	syscall
	ret
fprintf:
	mov r13, 1
	mov rax, r13
	mov rax, 0x02000004
	syscall
	ret
write:
	mov r13, 1
	mov r13, 1
	mov rdi, r13
	mov rax, 0x02000004
	syscall
	ret
print:
	mov rdx, rsi
	mov rsi, rdi
	mov r13, 1
	mov r13, 1
	mov rax, r13
	call write
	mov r13, newline
	mov r13, newline
	mov rsi, newline
	mov r13, 1
	mov r13, 1
	mov rdx, r13
	call write
	ret
open:
	mov r13, 2
	mov r13, 2
	mov rax, r13
	mov rax, 0x2000005
	syscall
	ret
close:
	mov r13, 3
	mov r13, 3
	mov rax, r13
	mov rax, 0x2000006
	syscall
	ret
start:
	mov r14, __w
	mov r13, msg
	mov r13, msg
	mov r13, msg
	mov rdi, msg
	mov r13, msglen
	mov r13, msglen
	mov r13, msglen
	mov rsi, msglen
	call print
	mov r13, 2
	mov r13, 2
	mov r13, 2
	mov rdi, r13
	inc rdi
	mov rdi, rdi
	push 4
	mov r14, rdi
	mov r14, r14
	imul r14, [rsp]
	mov r13, r14
	pop r14
	mov r14, rdi
	mov r14, r13
	mov r14, __w
	mov dx, 0
	mov rdi, 2
	idiv r14
	movzx r13, al
	mov qword [r14], r13
	mov r14, __w
	mov dx, 0
	mov rdi, 3
	idiv r14
	movzx r13, al
	mov qword [r14], r13
	mov r14, __w
	call exit
	mov rax, 0x02000001
	mov       rdi, 0
	syscall
	ret