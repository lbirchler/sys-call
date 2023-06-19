# syscall
---

## Usage
```
usage: syscall.py [-h] [--update] [arch] [syscall ...]

positional arguments:
  arch        arm, arm64, x64, x86
  syscall     syscall name or number

options:
  -h, --help  show this help message and exit
  --update    Update syscall db
```

## Examples

**Display single syscall**
```shell
./syscall.py x86 execve
```

```
                                                             x86 Syscalls
┏━━━━┳━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ nr ┃ name   ┃ return  eax ┃ arg0    ebx        ┃ arg1    ecx        ┃ arg2    edx         ┃ arg3    esi ┃ arg4    edi ┃ arg5    ebp ┃
┡━━━━╇━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ 11 │ execve │ 0x0b        │ const char         │ const char *const  │ const char *const   │             │             │             │
│    │        │             │ *filename          │ *argv              │ *envp               │             │             │             │
└────┴────────┴─────────────┴────────────────────┴────────────────────┴─────────────────────┴─────────────┴─────────────┴─────────────┘
```

**Display multiple syscalls**
```shell
./syscall.py x86 read write exit
```

```
                                                      x86 Syscalls
┏━━━━┳━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ nr ┃ name  ┃ return  eax ┃ arg0    ebx     ┃ arg1    ecx     ┃ arg2    edx  ┃ arg3    esi ┃ arg4    edi ┃ arg5    ebp ┃
┡━━━━╇━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ 3  │ read  │ 0x03        │ unsigned int fd │ char *buf       │ size_t count │             │             │             │
│ 4  │ write │ 0x04        │ unsigned int fd │ const char *buf │ size_t count │             │             │             │
│ 1  │ exit  │ 0x01        │ int error_code  │                 │              │             │             │             │
└────┴───────┴─────────────┴─────────────────┴─────────────────┴──────────────┴─────────────┴─────────────┴─────────────┘
```