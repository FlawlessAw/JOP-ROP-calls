.code

JopCall PROC
   push rbp
   mov rbp, rsp
   sub rsp, 20h
   
   push rsi
   push rdi
   mov rsi, rcx
   mov rdi, rdx
   
   mov rax, [rbp+8]
   
   push qword ptr [rsi+18h]
   push qword ptr [rsi+10h]
   push qword ptr [rsi+08h]
   push rax
   
   mov rcx, r8
   mov rdx, r9
   mov r8, [rbp+30h]
   mov r9, [rbp+38h]
   
   mov r10, rcx
   mov rcx, [rdi+8]
   
   mov eax, dword ptr [rdi]
   
   mov r11, qword ptr [rsi]
   
   pop rdi
   pop rsi
   
   jmp r11

JopCall ENDP

END
