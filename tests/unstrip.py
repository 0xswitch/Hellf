from Hellf import *
from Hellf.lib import Elf64_Shdr_ST

from struct import pack
from switch import hx

from sys import argv

class unstrip():

    def __init__(self, in_binary, out_binary):
        self.stripped_binary = ELF(in_binary)
        self.unstripped_binary = out_binary

        self.symtab_data = b"\x00" * 24
        self.strtab_data = b"\x00"

        self.text_section_number = self.stripped_binary.get_section_number(".text")

    def new_strtab_value(self, name):
        name = name.encode("utf-8")

        offset = self.strtab_data.find(name)

        if offset != -1:
            return offset
        else:
            self.strtab_data += name + b"\x00"
            return self.strtab_data.find(name)


    def add_function(self, name, value, size=0):
        new_function = b""
        new_function += pack("<I", self.new_strtab_value(name))
        new_function += pack("<B", 0x12)                            # STB_GLOBAL | STT_FUNC
        new_function += pack("<B", 0)
        new_function += pack("<H", self.text_section_number)
        new_function += pack("<Q", value)
        new_function += pack("<Q", size)

        self.symtab_data += new_function

    def save(self):

        # symtab section
        symtab = Elf64_Shdr_ST()
        symtab.sh_name = 1
        symtab.sh_type = 0x2                                          # symtab
        symtab.sh_offset = self.stripped_binary.Elf64_Ehdr.e_shoff
        symtab.sh_size = len(self.symtab_data)
        symtab.sh_addralign = 8
        symtab.sh_link = self.stripped_binary.Elf64_Ehdr.e_shnum + 1
        symtab.sh_info = 1
        symtab.sh_entsize = 0x18

        symtab.data = self.symtab_data

        self.stripped_binary.add_section(symtab)

        # strtab section
        strtab = Elf64_Shdr_ST()
        strtab.sh_name = 1
        strtab.sh_type = 0x3                                    # strtab
        strtab.sh_offset = self.stripped_binary.Elf64_Ehdr.e_shoff
        strtab.sh_size = len(self.strtab_data)
        strtab.sh_addralign = 1

        strtab.data = self.strtab_data

        self.stripped_binary.add_section(strtab)

        self.stripped_binary.save(self.unstripped_binary)


if __name__ == "__main__":

    naked = unstrip(argv[1], argv[2])
    naked.add_function("bite", 0x401159)
    naked.save()


# except behavior:
# - 2 sections added
# nm unstripped
# 0000000000401146 T acab
# 0000000000401159 T hello
