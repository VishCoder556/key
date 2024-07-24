global start

section .data
	__w: dw 0
	newline: db  "", 10, ""
	a resb 8
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
ret
ret
start:
	mov r14, __w
	mov byte [r14 + 2], 10
	mov qword [r14 + 1], 8
	push 8
	mov rdi, qword [r14 + 1]
	mov r14, __w
	
	inc rdi
	mov rdi, rdi
	call exit
	mov rax, 0x02000001
	mov       rdi, 0
	syscall
	ret