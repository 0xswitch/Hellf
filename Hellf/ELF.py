#!/usr/bin/python3
from Hellf.lib.elf_structs import *
from Hellf.lib.consts import *

from binascii import hexlify
from struct import unpack

# todo :
# get segment by section
# try a real way to localize .shstrtab

class ELF:

    def __init__(selph, binary):
        selph.binary = binary

        if isinstance(binary, bytes):
            selph.elf_data = binary
        else:
            elf_hdl = open(binary, "rb")
            selph.elf_data = elf_hdl.read()

        # check architecture

        if selph.x86_or_x64() == X64:
            selph.archi_bits = X64
            selph.Elf64_Ehdr = Elf64_Ehdr_ST(selph)
            selph.ElfXX_Ehdr = selph.Elf64_Ehdr

            selph.Elf64_Phdr = Elf64_Phdr_LST(selph)
            selph.ElfXX_Phdr = selph.Elf64_Phdr

            selph.Elf64_Shdr = Elf64_Shdr_LST(selph)
            selph.ElfXX_Shdr = selph.Elf64_Shdr

        elif selph.x86_or_x64() == X32:
            selph.archi_bits = X32
            selph.Elf32_Ehdr = Elf32_Ehdr_ST(selph)
            selph.ElfXX_Ehdr = selph.Elf32_Ehdr

            selph.Elf32_Phdr = Elf32_Phdr_LST(selph)
            selph.ElfXX_Phdr = selph.Elf32_Phdr

            selph.Elf32_Shdr = Elf32_Shdr_LST(selph)
            selph.ElfXX_Shdr = selph.Elf32_Shdr

        else:
            print(error("wtf man"))
            exit(0)

    def __repr__(selph):
        return  "Hellf obj \n" + \
                f'{" " * 4}archi : {"x86" if selph.archi_bits == 1 else "x64"}\n' + \
                f'{" " * 4}path : {selph.binary}\n'

    def x86_or_x64(selph):
        return unpack("B", selph.elf_data[4:5])[0]

    @property
    def pie(self):
        return True if self.ElfXX_Ehdr.e_type == ET_DYN else False



    def get_section_number(selph, name):
        i = 0
        for sh in selph.ElfXX_Shdr:
            sh_name = selph.ElfXX_Shdr[-1].data[sh.sh_name:].split(b"\x00")[0].decode("utf-8") # last sh describe .shstrtab which contains sections names
            if sh_name == name:
                return i
            else:
                i += 1

    def get_section_by_name(selph, name):
        for sh in selph.ElfXX_Shdr:
            sh_name = selph.ElfXX_Shdr[-1].data[sh.sh_name:].split(b"\x00")[0].decode("utf-8") # last sh describe .shstrtab which contains sections names
            if sh_name == name:
                return sh

    def get_section_name(selph, offset):
        return selph.ElfXX_Shdr[-1].data[offset:].split(b"\x00")[0].decode("utf-8")

    # todo but hard has if a section size is modified (if larger because if smaller size_padded will automatically fill with 00 when save will be called)
    # the offset of the other in Shdr have to be updated
    def update_section(selph, section=None, section_name=None, value=None):
        pass

    def add_section(selph, custom_section):
        padding_size = custom_section.sh_addralign - (custom_section.sh_size % custom_section.sh_addralign)
        custom_section.data += b"\x00" * padding_size

        # print(padding_size)

        # update nb of Shdr entry of Shdrt in Ehdr.e_shnum
        selph.ElfXX_Ehdr.e_shnum += 1
        # adding the custom section to the list
        selph.ElfXX_Shdr.append(custom_section)
        # saving the binary will add the section after every other sections, and so the Shdrt location will
        # be moved of the size of the data from the new section.
        selph.ElfXX_Ehdr.e_shoff += custom_section.sh_size + padding_size

        # we added padding for alignment so we must include it in section size.
        custom_section.sh_size += padding_size


    def save(selph, output_location):

        buff = selph.ElfXX_Ehdr.save()

        total = selph.ElfXX_Ehdr.e_ehsize
        # n_ElfXX_Ehdr = selph.ElfXX_Ehdr.save()
        pht_size = selph.ElfXX_Ehdr.e_phnum * selph.ElfXX_Ehdr.e_phentsize
        sht_size = selph.ElfXX_Ehdr.e_shnum * selph.ElfXX_Ehdr.e_shentsize

        # adding each ph to the ELF
        for i in range(selph.ElfXX_Ehdr.e_phnum):
            buff += selph.ElfXX_Phdr[i].save()

        # it may have some padding between last phdr and data section
        just_after_last_phdr = selph.ElfXX_Ehdr.e_phoff + selph.ElfXX_Ehdr.e_phnum * selph.ElfXX_Ehdr.e_phentsize


        # data_addr = selph.Elf64_Shdr[1].sh_offset # 0 is often (always ?) nulltype so using 1 which point to data first byte.
        # sometimes sections are not in the right order of offset in the sht

        # Section Headers:
        # [Nr] Name                 Type         Addr             Off      Size     ES Flags Lk Inf Al
        # [ 0]                      NULL         0000000000000000 00000000 00000000  0        0   0  0
        # [ 1] .text                PROGBITS     0000000000401100 00001100 00000665  0 AX     0   0 16
        # [ 2] .interp              PROGBITS     00000000004002a8 000002a8 0000001c  0 A      0   0  1
        # [ 3] .note.gnu.build-id   NOTE         00000000004002c4 000002c4 00000024  0 A      0   0  4
        # [ 4] .note.ABI-tag        NOTE         00000000004002e8 000002e8 00000020  0 A      0   0  4
        # [ 5] .gnu.hash            GNU_HASH     0000000000400308 00000308 0000001c  0 A      6   0  8
        # [ 6] .dynsym              DYNSYM       0000000000400328 00000328 000001b0 24 A      7   1  8
        # [ 7] .dynstr              STRTAB       00000000004004d8 000004d8 00000152  0 A      0   0  1
        # [ 8] .gnu.version         GNU_versym   000000000040062a 0000062a 00000024  2 A      6   0  2
        # [ 9] .gnu.version_r       GNU_verneed  0000000000400650 00000650 00000060  0 A      7   2  8

        sorted_section_by_offset = sorted([ sh for sh in selph.ElfXX_Shdr ], key=lambda section: section.sh_offset)
        data_addr = sorted_section_by_offset[1].sh_offset

        buff += b"\x00" * (data_addr - just_after_last_phdr)

        # adding all data described by sections to the ELF

        # sometimes sections are not in the right order of offset in the sht
        actual_sh = sorted([ selph.ElfXX_Shdr[i] for i in range(selph.ElfXX_Ehdr.e_shnum) ], key=lambda sh: sh.sh_offset)

        for i in range(selph.ElfXX_Ehdr.e_shnum):

            # if sh data is modified and size less than previous size,
            # we need to pad with \x00 to keep the initial size
            # we need to keep the initial size else the offset for the next sh would change

            # custom section haven't got padded size attribute as sh_size is the real size so skipping this check

            if hasattr(actual_sh[i], "size_padded"):

                if len(actual_sh[i].data) != actual_sh[i].size_padded:
                    actual_sh[i].data += b"\x00" * (actual_sh[i].size_padded - len(actual_sh[i].data))

            buff += actual_sh[i].data

            # sometime there is padding between section, so just calculating the difference between two section and adding \x00
            if actual_sh[i].sh_type not in [0x00, 0x08]: # these type of section do not have space on file, only at runtime


                if i != selph.ElfXX_Ehdr.e_shnum - 1:

                    # if a NOBITS section is between 2 PROGBITS the padding can be invald

                    j = 1

                    next_section = actual_sh[i+j]

                    # so we are getting the next section which actually hold data (skipping NOBITS one)
                    while next_section.sh_type in [0x00, 0x08]:
                        j += 1
                        next_section = actual_sh[i+j]

                    pad_size =  (next_section.sh_offset - (actual_sh[i].sh_offset + actual_sh[i].sh_size))
                    buff += b"\x00" * pad_size
                else:
                    pad_size = (selph.ElfXX_Ehdr.e_shoff - (actual_sh[i].sh_offset + actual_sh[i].sh_size))
                    # print(pad_size)
                    buff += b"\x00" * pad_size

        # adding each sh to the ELF
        for i in range(selph.ElfXX_Ehdr.e_shnum):
            buff += selph.ElfXX_Shdr[i].save()

        open(output_location, "wb").write(buff)
