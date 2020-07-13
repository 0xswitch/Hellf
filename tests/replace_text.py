from Hellf import ELF
from pwn import shellcraft, asm, context
from sys import argv

context.arch = "amd64"

e = ELF(argv[1])
e.get_section_by_name(".text").data = asm(shellcraft.amd64.sh())
e.Elf64_Ehdr.e_entry = e.get_section_by_name(".text").sh_addr
e.save(argv[2])

# excepted behavior :
# - pop a shell
