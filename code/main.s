global start

section .data
	__w: dw 0
	newline: db  "", 10, ""
	msg: db  "Hello Worlds"
section .text
_strlen_start:
	cmp word [r12], 0
	je _strlen_end
	inc r12
	inc r11
	jmp _strlen_start
	ret
_strlen_end:
	mov rax, 0
	ret
strlen:
	mov r11, 0 ;; counter
	mov r12, rsi
	call _strlen_start
	mov rsi, r11
	ret

dig1_to_str:
	add dil, '0'
	call char_to_str
	ret


char_to_str:
	sub rsp, 16
	mov al, dil
	mov byte [rsp], al
	mov byte [rsp+1], 0
	lea rdi, [rsp]
	add rsp, 16
	ret








int_to_str:
	push rbx
	push rdx

	mov rbx, rdi
	mov rax, rdi
	sub rsp, 32
	cmp rbx, 0
	jne _int_to_str_convert_loop
	mov byte [rsp], '0'
	mov byte [rsp+1], 0
	lea rdi, [rsp]
	jmp _int_to_str_end

_int_to_str_convert_loop:
	mov rdi, rsp
	add rdi, 30
	mov byte [rdi+1], 0

	test rbx, rbx
	mov byte [rsp - 1], '-'
	jns _int_to_str_int_to_str_convert_digits
	neg rax
	dec rdi

_int_to_str_int_to_str_convert_digits:
	mov rcx, 10
_int_to_str_convert_digit_loop:
	xor rdx, rdx
	div rcx
	add dl, '0'
	mov [rdi], dl
	dec rdi
	test rax, rax
	jnz _int_to_str_convert_digit_loop
	lea rdi, [rdi+1]

_int_to_str_end:
	add rsp, 32
	pop rdx
	pop rbx
	ret
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
_print:
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
print:
	mov rsi, rdi
	call strlen
	call _print
	ret
println:
	mov rsi, rdi
	call strlen
	call _print
	mov r13, 1
	mov r13, 1
	mov rsi, r13
	mov r13, newline
	mov r13, newline
	mov rdi, newline
	call _print
	ret
open:
	start:
	mov r14, __w
	mov r13, msg
	mov r13, msg
	mov r13, msg
	mov rdi, msg
	call print
	mov r13, 10
	mov r13, 10
	mov r13, 10
	mov rdi, r13
	call exit
	mov rax, 0x02000001
	mov       rdi, 0
	syscall
	ret