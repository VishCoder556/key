global start
section .data
	__w: dw 0
section .text
start:
	mov r14, __w
	mov r15, 57
mov rdi, r15
	mov r15, 60
mov rax, r15
	mov r15, 5
	mov r15, r15
	mov r15, 5
	mov r14, r15
	cmp r14, r15
	setge    al
	movzx r15, al
	mov r14, __w
	test r15, r15
	jz end_18
push 5
	mov r15, rdi
	inc r15
mov rdi, r15
	jmp end_18
end_18:
	mov rax, 0x02000001
	syscall
	ret
