# Hellf
> this is just a bad joke between hell and elf :(

The aim of this project is to provide a python library for patching ELF binary file

```python
from Hellf import ELF
from pwn import shellcraft, asm, context
context.arch = "amd64"

e = ELF("/bin/ls")
e.get_section_by_name(".text").data = asm(shellcraft.amd64.sh())
e.Elf64_Ehdr.e_entry = e.get_section_by_name(".text").sh_addr
e.save("/tmp/not_really_ls_anymore")
```

There is not documentation for the moment althought the code is a bit commented.

For the names of variables I just used the official one provided by the ABI.

- /usr/include/elf.h
- [http://www.sco.com/developers/gabi/latest/contents.html](http://www.sco.com/developers/gabi/latest/contents.html)


For example, the ELF Header :
```
typedef struct
{
  unsigned char e_ident[EI_NIDENT];     /* Magic number and other info */
  Elf64_Half    e_type;                 /* Object file type */
  Elf64_Half    e_machine;              /* Architecture */
  Elf64_Word    e_version;              /* Object file version */
  Elf64_Addr    e_entry;                /* Entry point virtual address */
  Elf64_Off     e_phoff;                /* Program header table file offset */
  Elf64_Off     e_shoff;                /* Section header table file offset */
  Elf64_Word    e_flags;                /* Processor-specific flags */
  Elf64_Half    e_ehsize;               /* ELF header size in bytes */
  Elf64_Half    e_phentsize;            /* Program header table entry size */
  Elf64_Half    e_phnum;                /* Program header table entry count */
  Elf64_Half    e_shentsize;            /* Section header table entry size */
  Elf64_Half    e_shnum;                /* Section header table entry count */
  Elf64_Half    e_shstrndx;             /* Section header string table index */
} Elf64_Ehdr;
```


![img/poc.gif](img/poc.gif)
