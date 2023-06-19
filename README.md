# syscall
---

## Usage
```
usage: syscall.py [-h] [-a {arm,arm64,x64,x86}] {info,shellcode} ...

positional arguments:
  {info,shellcode}
    info                syscall info
    shellcode           Search shell-storm for shellcode examples

options:
  -h, --help            show this help message and exit
  -a {arm,arm64,x64,x86}, --arch {arm,arm64,x64,x86} 
                          default x64
```

## Examples

### Info

For single syscall
```
$ ./syscall.py info execve
                                                                  x64 Syscalls                                                                  
┏━━━━┳━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ nr ┃ name   ┃ return  rax ┃ arg0    rdi          ┃ arg1    rsi             ┃ arg2    rdx             ┃ arg3    r10 ┃ arg4    r8 ┃ arg5    r9 ┃
┡━━━━╇━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ 59 │ execve │ 0x3b        │ const char *filename │ const char *const *argv │ const char *const *envp │             │            │            │
└────┴────────┴─────────────┴──────────────────────┴─────────────────────────┴─────────────────────────┴─────────────┴────────────┴────────────┘
```

For multiple syscalls
```
$ ./syscall.py info read write exit
                                                        x64 Syscalls                                                        
┏━━━━┳━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ nr ┃ name  ┃ return  rax ┃ arg0    rdi          ┃ arg1    rsi     ┃ arg2    rdx  ┃ arg3    r10 ┃ arg4    r8 ┃ arg5    r9 ┃
┡━━━━╇━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ 2  │ open  │ 0x02        │ const char *filename │ int flags       │ umode_t mode │             │            │            │
│ 0  │ read  │ 0x00        │ unsigned int fd      │ char *buf       │ size_t count │             │            │            │
│ 1  │ write │ 0x01        │ unsigned int fd      │ const char *buf │ size_t count │             │            │            │
│ 60 │ exit  │ 0x3c        │ int error_code       │                 │              │             │            │            │
└────┴───────┴─────────────┴──────────────────────┴─────────────────┴──────────────┴─────────────┴────────────┴────────────┘
```

For all syscalls
```
$ ./syscall.py info
                                                               x64 Syscalls                                                                
┏━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ nr  ┃ name           ┃ return  rax ┃ arg0    rdi    ┃ arg1    rsi    ┃ arg2    rdx    ┃ arg3    r10    ┃ arg4    r8    ┃ arg5    r9     ┃
┡━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ 67  │ shmdt          │ 0x43        │ char *shmaddr  │                │                │                │               │                │
│ 112 │ setsid         │ 0x70        │                │                │                │                │               │                │
│ 68  │ msgget         │ 0x44        │ key_t key      │ int msgflg     │                │                │               │                │
│ 0   │ read           │ 0x00        │ unsigned int   │ char *buf      │ size_t count   │                │               │                │
│     │                │             │ fd             │                │                │                │               │                │
│ 1   │ write          │ 0x01        │ unsigned int   │ const char     │ size_t count   │                │               │                │
│     │                │             │ fd             │ *buf           │                │                │               │                │
...
```

Update syscall database
```
./syscall.py info --update
[+] Saved syscall db to: ./syscalldb.json
```

### Shellcode

Search for x86 execve shellcode examples
```
$ ./syscall.py shellcode execve
                                                      x86 Shellcode 
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━┓
┃ author                        ┃ platform     ┃ desc                                                              ┃ id  ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━┩
│ ZadYree, vaelio and DaShrooms │ Linux/x86-64 │ execveat("/bin//sh") - 29 bytes                                   │ 905 │
│ 10n1z3d                       │ Linux/x86-64 │ execve(/sbin/iptables, [/sbin/iptables, -F], NULL) - 49 bytes     │ 683 │
│ egeektronic                   │ Linux/x86-64 │ setreuid(0,0) execve(/bin/ash,NULL,NULL) + XOR - 85 bytes         │ 815 │
│ egeektronic                   │ Linux/x86-64 │ setreuid(0,0) execve(/bin/csh, [/bin/csh, NULL]) + XOR - 87 bytes │ 816 │
│ egeektronic                   │ Linux/x86-64 │ setreuid(0,0) execve(/bin/ksh, [/bin/ksh, NULL]) + XOR - 87 bytes │ 817 │
│ egeektronic                   │ Linux/x86-64 │ setreuid(0,0) execve(/bin/zsh, [/bin/zsh, NULL]) + XOR - 87 bytes │ 818 │
│ evil.xi4oyu                   │ Linux/x86-64 │ setuid(0) + execve(/bin/sh) 49 bytes                              │ 77  │
│ hophet                        │ Linux/x86-64 │ execve(/bin/sh, [/bin/sh], NULL) - 33 bytes                       │ 76  │
│ zbt                           │ Linux/x86-64 │ execve(/bin/sh); - 30 bytes                                       │ 603 │
└───────────────────────────────┴──────────────┴───────────────────────────────────────────────────────────────────┴─────┘
```

Download shellcode example 
```
$ ./syscall.py shellcode --get 76

# [Linux/X86-64]
# Dummy for shellcode:
# execve("/bin/sh", ["/bin/sh"], NULL)
# hophet [at] gmail.com

.text
	.globl _start
_start:
	
	xorq	%rdx, %rdx
	movq	$0x68732f6e69622fff,%rbx
	shr	$0x8, %rbx
	push	%rbx
	movq	%rsp,%rdi
	xorq	%rax,%rax
	pushq	%rax
	pushq	%rdi
	movq	%rsp,%rsi
	mov	$0x3b,%al	# execve(3b)
	syscall

	pushq	$0x1
	pop	%rdi
	pushq	$0x3c		# exit(3c)
	pop	%rax
	syscall

```

