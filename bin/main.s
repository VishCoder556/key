global start
section .data
	__w: dw 0
	x: dq 5
section .text
start:
	mov r14, __w
		mov rax, 60
		mov r15, qword [r14 + 2]
	mov r14, 9
	cmp r14, r15
	setg    al
	movzx r15, al
	mov r14, __w
mov rdi, r15
	mov rax, 0x02000001
	syscall
	ret
