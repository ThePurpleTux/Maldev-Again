; Hell's Gate
; Dynamic system call invocation 
; 
; by smelly__vx (@RtlMateusz) and am0nsec (@am0nsec)
; https://github.com/am0nsec/HellsGate/blob/master/HellsGate/hellsgate.asm


.data
	wSystemCall DWORD 000h          ; global variable used to keep the SSN of a syscall

.code 
	HellsGate PROC                  ; updating the 'wSystemCall' variable with input argument (ecx register's value)
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	HellsGate ENDP

	HellDescent PROC                ; Calls the syscall that corresponds to the SSN in wSystemCall.
		mov r10, rcx
		mov eax, wSystemCall        ; wSystemCall` is the SSN of the syscall to call

		syscall
		ret
	HellDescent ENDP
end
