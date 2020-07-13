#!/usr/bin/python3
from Hellf import ELF
from Hellf.lib import Elf64_Shdr_ST

from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KS_OPT_SYNTAX_NASM
from ctypes import c_char

from sys import argv
from IPython import embed
from pprint import pprint as pp
from huepy import good

###
# Aim :
# add a section with our shellcode,
# extend a segment to map this new section in RWX memory
# update the entrypoint to jmp to the shellcode
##

e = ELF(argv[1])

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

# we can modify the .text section to jmp to the sc but we will directly modified the entrypoint
# stub = ks.asm("jmp 0x3308")[0]
# stub = (c_char * len(stub)).from_buffer(bytearray(stub)).raw
# e.get_section_by_name(".text").data = stub

new_section.data = shellcode

new_section.sh_name = 1 # choose a random name
# right after the last sh there is the sht table so it offset will be the addr of the new section
new_section.sh_offset = e.Elf64_Ehdr.e_shoff # nice if it would be filled automatically by save
new_section.sh_size = len(new_section.data)
new_section.sh_addralign = 16
new_section.sh_type = 0x1 # PROGBITS

# adding our sections in the Shdt
e.add_section(new_section)

# need to extend the last segment to englobe our new section
segment = e.Elf64_Phdr[5]
segment.p_filesz = new_section.sh_offset + new_section.sh_size - segment.p_offset
segment.p_memsz = new_section.sh_offset + new_section.sh_size - segment.p_offset

segment.p_flags = 7 # RWX

# modifying our entrypoint to point to the shellcode
e.Elf64_Ehdr.e_entry = segment.p_vaddr - segment.p_offset + new_section.sh_offset
print(good("Entry at {}".format(hex(e.Elf64_Ehdr.e_entry))))

e.save(argv[2])

# excepted behavior:
# - return 14  (echo $?)
