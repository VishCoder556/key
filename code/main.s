global start

section .data
	__w: dw 0
	newline: db  "", 10, ""
	msg: db  "Hello World"
	msglen equ  $ - msg
section .text
exit:
	mov rax, 60
	mov rax, 0x02000001
	syscall
	ret
fprintf:
	mov rax, 1
	mov rax, 0x02000004
	syscall
	ret
write:
	mov r13, 1
	mov rdi, 1
	mov rax, 0x02000004
	syscall
	ret
print:
	mov rdx, rsi
	mov rsi, rdi
	mov r13, 1
	mov rax, 1
	call write
	mov r13, newline
	mov rsi, newline
	mov r13, 1
	mov rdx, 1
	call write
	ret
open:
	mov r13, 2
	mov rax, 2
	mov rax, 0x2000005
	syscall
	ret
close:
	mov r13, 3
	mov rax, 3
	mov rax, 0x2000006
	syscall
	ret
start:
	mov r14, __w
	mov r13, 5
	mov r13, 5
	mov rax, 5
	mov r15, rax
	mov r13, 6
	mov r14, r13
	cmp r14, r15
	jg end_104
	mov r14, __w
	cmp r13, r13
	push 6
	mov r13, msg
	mov r13, msg
	mov rdi, msg
	mov r13, msglen
	mov r13, msglen
	mov rsi, msglen
	call print
	jmp end_104
end_104:
	mov r13, 10
	mov r13, 10
	mov rdi, 10
	call exit
	mov rax, 0x02000001
	mov       rdi, 0
	syscall
	ret