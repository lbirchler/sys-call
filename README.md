# sys-call

CLI tool to display Linux syscall implementations, calling conventions, and shellcode examples.

Supported Architectures: 
- arm
- arm64
- x86
- x64

Data Sources:
- Syscall implementations and calling conventions: [syscall.sh](https://syscall.sh) 
- Shellcode Examples: [shell-storm](http://shell-storm.org/shellcode/index.html)

## Install
```
pip install sys-call
```

## Usage 
```
usage: sys-call [-h] [-a {arm,arm64,x64,x86}] {shellcode,info} ...

positional arguments:
  {shellcode,info}      commands

options:
  -h, --help            show this help message and exit
  -a {arm,arm64,x64,x86}, --arch {arm,arm64,x64,x86}
                                 defaults to x64
```

### `sys-call info`
```
usage: sys-call info [-h] [--update] [syscall ...]

positional arguments:
  syscall     syscall name(s)

options:
  -h, --help  show this help message and exit
  --update    Update syscall database
```

**Examples**

For single syscall:
```
$ sys-call info execve
                                                                  x64 Syscalls                                                                  
┏━━━━┳━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ nr ┃ name   ┃ return  rax ┃ arg0    rdi          ┃ arg1    rsi             ┃ arg2    rdx             ┃ arg3    r10 ┃ arg4    r8 ┃ arg5    r9 ┃
┡━━━━╇━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ 59 │ execve │ 0x3b        │ const char *filename │ const char *const *argv │ const char *const *envp │             │            │            │
└────┴────────┴─────────────┴──────────────────────┴─────────────────────────┴─────────────────────────┴─────────────┴────────────┴────────────┘
```

For multiple syscalls:
```
$ sys-call info open read write
                                                        x64 Syscalls                                                        
┏━━━━┳━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ nr ┃ name  ┃ return  rax ┃ arg0    rdi          ┃ arg1    rsi     ┃ arg2    rdx  ┃ arg3    r10 ┃ arg4    r8 ┃ arg5    r9 ┃
┡━━━━╇━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ 2  │ open  │ 0x02        │ const char *filename │ int flags       │ umode_t mode │             │            │            │
│ 0  │ read  │ 0x00        │ unsigned int fd      │ char *buf       │ size_t count │             │            │            │
│ 1  │ write │ 0x01        │ unsigned int fd      │ const char *buf │ size_t count │             │            │            │
└────┴───────┴─────────────┴──────────────────────┴─────────────────┴──────────────┴─────────────┴────────────┴────────────┘
```

For all syscalls:
```
$ sys-call info 
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

Update sys-call database:
```
$ sys-call info --update
[+] Updated x64 syscalls
[+] Updated arm64 syscalls
[+] Updated arm syscalls
[+] Updated x86 syscalls
[+] Saved syscall db to: ./syscalldb.json
```

### `sys-call shellcode`
```
usage: sys-call shellcode [-h] [--get GET] [syscall ...]

positional arguments:
  syscall     syscall name(s)

options:
  -h, --help  show this help message and exit
  --get GET   download shell-storm example; specify id
```

**Examples**

Search for execve shellcode examples:
```
$ sys-call shellcode execve
                                                      x64 Shellcode 
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

Download shellcode example: 
```
$ sys-call shellcode --get 76

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

