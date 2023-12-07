# Syscalls

Syscalls can be called in many different ways and using many different techniques.
The biggest difference is direct vs indect syscalls. 
Using direct syscalls means you include the syscall instruction in your binary. This ispotentially a very big IoC.
Using Indirect syscalls means you jump to a legit syscall instruction in NTDLL. While better than direct syscalls, this can also be detected.
