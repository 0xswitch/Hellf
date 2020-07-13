# Hellf v1.1 ![](./img/logo.png)



this is just a bad joke between hell and elf :(

The aim of this project is to provide a python library for patching ELF binary file. It only supports for the moment `x86` and `x86_64` architecture.



[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/) [![Ask Me Anything !](https://img.shields.io/badge/Ask%20me-anything-1abc9c.svg)](https://GitHub.com/Naereen/ama) ![Twitter Follow](https://img.shields.io/twitter/follow/swuitch?label=ping%20%40swuitch&style=social)

```python
from Hellf import ELF
from pwn import shellcraft, asm, context
context.arch = "amd64"

e = ELF("/bin/ls")

e.get_section_by_name(".text").data = asm(shellcraft.amd64.sh())
e.Elf64_Ehdr.e_entry = e.get_section_by_name(".text").sh_addr

e.save("/tmp/not_really_ls_anymore")
```

![img/poc.gif](img/twitter.gif)

# Use cases

Hellf allows you to modify each par of the ELF.

- Program Header (segments definitions)
- Section Header (sections definitions)
- Section data (.text, .plt, .data, .bss, ...)

You can change every single byte of a given binary.

## Adding a section

```python
new_section = Elf64_Shdr_ST()

# creating our shellcode (exit(14);)
asm = """
    mov rax, 0x3c
    mov rdi, 14
    syscall
    """

ks = Ks(KS_ARCH_X86, KS_MODE_64)
ks.syntax = KS_OPT_SYNTAX_NASM

shellcode = ks.asm(asm)[0]
shellcode = (c_char * len(shellcode)).from_buffer(bytearray(shellcode)).raw

new_section.data = shellcode

new_section.sh_name       = 1                      # choose a random name
new_section.sh_offset     = e.Elf64_Ehdr.e_shoff
new_section.sh_size       = len(new_section.data)
new_section.sh_addralign  = 16
new_section.sh_type       = 0x1                    # PROGBITS

# adding our sections in the Section Header table
e.add_section(new_section)
```

## Extending segment

```Python
# need to extend the last segment to englobe our new section
segment = e.Elf64_Phdr[5]

segment.p_filesz 	= new_section.sh_offset + new_section.sh_size - segment.p_offset
segment.p_memsz 	= new_section.sh_offset + new_section.sh_size - segment.p_offset
segment.p_flags 	= 7 # RWX

# modifying our entrypoint to point to the shellcode
e.Elf64_Ehdr.e_entry = segment.p_vaddr - segment.p_offset + new_section.sh_offset

e.save("/tmp/exit")
```

# Embuche

Hellf is a part of [Embuche](https://github.com/magnussen7/Embuche), a lot of Hellf scripts are used to obfuscate ELF for the purpose of this project. The scripts used are described here : [File Format Hacks](https://github.com/magnussen7/Embuche/blob/master/README.md#file-format-hacks)

For example it used to create a fake `.dynsym` section or to hide the entry point [link to script](https://github.com/magnussen7/Embuche/blob/master/class_embuche/cmake_bakery/hellf_scripts/mixing_symbols_table.py)

But Hellf is also the corner stone of the Embuche metamorphic packer.

> A metamorphic packer is available in Embuche. This packer will load your binary and cipher it (AES 256 bits CBC).
>
> If you decide to use the packer, your program will be ciphered and stored in a section of our packer. When you will execute your program the packer will copy itself in memory, unciphered your program and write it on the disk for execution.
>
> Beside cipher your binary, the packer will also ensure its integrity. The encryption keys used for the encryption are based on the SHA sum of the `.text` section, so if the packer or your program is being debugged the SHA sum will be different of the one used for decryption.
>
> The ELF of the packer can be modified with the `packer_embuche` options.

# Documentation

There is almost no documentation for the moment although the code is a bit commented, you should be lucky.

Here a list of function of the `ELF` object.

```python
get_section_number(name)
get_section_by_name(name)
get_section_name(shstrtab_index)
add_section(custom_section)
```

For the remaining, you should just interact with the object attributes them self. About the names of variables I just used the official one provided by the ABI.

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

So you can just do this to interact with the section or section header :

```python
>  e.Elf64_Shdr[26]
ELF Sections header struct
  sh_name:      0x1
  sh_type:      0x3
  sh_flags:     0x0
  sh_addr:      0x0
  sh_offset:    0x222b4
  sh_size:      0xf7
  sh_link:      0x0
  sh_info:      0x0
  sh_addralign: 0x1
  sh_entsize:   0x0

> e.Elf64_Shdr[26].data
b'\x00.shstrtab\x00.interp\x00.note.gnu.build-id\x00.note.ABI-tag\x00.gnu.hash\x00.dynsym\x00.dynstr\x00.gnu.version\x00.gnu.version_r\x00.rela.dyn\x00.rela.plt\x00.init\x00.text\x00.fini\x00.rodata\x00.eh_frame_hdr\x00.eh_frame\x00.init_array\x00.fini_array\x00.data.rel.ro\x00.dynamic\x00.got\x00.data\x00.bss\x00.comment\x00'

> e.get_section_name(e.Elf64_Shdr[26].sh_name)
'.shstrtab'
```

Or if you want to interact with the header itself.

````python
> e.Elf64_Ehdr
ELF Header struct
  e_ident:      0x7f 0x45 0x4c 0x46 0x2 0x1 0x1 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0
  e_type:       0x3
  e_machine:    0x3e
  e_version:    0x1
  e_entry:      0x5b20
  e_phoff:      0x40
  e_shoff:      0x2234b
  e_flags:      0x0
  e_ehsize:     0x40
  e_phentsize:  0x38
  e_phnum:      0xb
  e_shentsize:  0x40
  e_shnum:      0x1b
  e_shstrndx:   0x1a

> hex(e.Elf64_Ehdr.e_entry)
'0x5b20'

> hex(e.Elf64_Ehdr.e_shnum)
'0x1b'

> hex(e.Elf64_Ehdr.e_shoff)
'0x2234b'
````
