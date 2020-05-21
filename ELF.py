#!/usr/bin/python3
from Hellf.lib.elf_structs import *

from binascii import hexlify
from huepy import *

# todo :
# get segment by section
# try a real way to localize .shstrtab


class ELF:

    def __init__(selph, binary):

        if isinstance(binary, bytes):
            selph.elf_data = binary
        else:
            elf_hdl = open(binary, "rb")
            selph.elf_data = elf_hdl.read()

        selph.Elf64_Ehdr = Elf64_Ehdr_ST(selph)
        selph.Elf64_Phdr = Elf64_Ehdr_LST(selph)
        selph.Elf64_Shdr = Elf64_Shdr_LST(selph)

    def get_section_by_name(selph, name):
        # print(selph.Elf64_Shdr[-1].data)
        for sh in selph.Elf64_Shdr:
            sh_name = selph.Elf64_Shdr[-1].data[sh.sh_name:].split(b"\x00")[0].decode("utf-8") # last sh describe .shstrtab which contains sections names
            if sh_name == name:
                return sh

    def get_section_name(selph, offset):
        return selph.Elf64_Shdr[-1].data[offset:].split(b"\x00")[0].decode("utf-8")

    # todo but hard has if a section size is modified (if larger because if smaller size_padded will automatically fill with 00 when save will be called)
    # the offset of the other in Shdr have to be updated
    def update_section(selph, section=None, section_name=None, value=None):
        pass

    def add_section(selph, custom_section):
        padding_size = custom_section.sh_addralign - (custom_section.sh_size % custom_section.sh_addralign)
        custom_section.data += b"\x00" * padding_size

        # update nb of Shdr entry of Shdrt in Ehdr.e_shnum
        selph.Elf64_Ehdr.e_shnum += 1
        # adding the custom section to the list
        selph.Elf64_Shdr.append(custom_section)
        # saving the binary will add the section after every other sections, and so the Shdrt location will
        # be moved of the size of the data from the new section.
        selph.Elf64_Ehdr.e_shoff += custom_section.sh_size + padding_size


    def save(selph, output_location):

        buff = selph.Elf64_Ehdr.save()

        total = selph.Elf64_Ehdr.e_ehsize
        # n_Elf64_Ehdr = selph.Elf64_Ehdr.save()
        pht_size = selph.Elf64_Ehdr.e_phnum * selph.Elf64_Ehdr.e_phentsize
        sht_size = selph.Elf64_Ehdr.e_shnum * selph.Elf64_Ehdr.e_shentsize

        # adding each ph to the ELF
        for i in range(selph.Elf64_Ehdr.e_phnum):
            buff += selph.Elf64_Phdr[i].save()

        # it may have some padding between last phdr and data section
        just_after_last_phdr = selph.Elf64_Ehdr.e_phoff + selph.Elf64_Ehdr.e_phnum * selph.Elf64_Ehdr.e_phentsize


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

        sorted_section_by_offset = sorted([ sh for sh in selph.Elf64_Shdr ], key=lambda section: section.sh_offset)
        data_addr = sorted_section_by_offset[1].sh_offset

        buff += b"\x00" * (data_addr - just_after_last_phdr)
        # print(hex(len(buff)))

        # adding all data described by sections to the ELF

        # sometimes sections are not in the right order of offset in the sht
        actual_sh = sorted([ selph.Elf64_Shdr[i] for i in range(selph.Elf64_Ehdr.e_shnum) ], key=lambda sh: sh.sh_offset)

        for i in range(selph.Elf64_Ehdr.e_shnum):

            # if sh data is modified and size less than previous size,
            # we need to pad with \x00 to keep the initial size
            # we need to keep the initial size else the offset for the next sh would change

            # custom section haven't got padded size attribute as sh_size is the real size so skipping this check
            if hasattr(actual_sh[i], "size_padded"):

                if len(actual_sh[i].data) != actual_sh[i].size_padded:
                    actual_sh[i].data += b"\x00" * (actual_sh[i].size_padded - len(actual_sh[i].data))

            buff += actual_sh[i].data

            # sometime there is padding between section, so just calculating the differnce between two section and adding \x00
            if actual_sh[i].sh_type not in [0x00, 0x08]: # these type of section do not have space on file only at runtime
                if i != selph.Elf64_Ehdr.e_shnum - 1:
                    buff += b"\x00" * (actual_sh[i+1].sh_offset - (actual_sh[i].sh_offset + actual_sh[i].sh_size))
                else:
                    buff += b"\x00" * (selph.Elf64_Ehdr.e_shoff - (actual_sh[i].sh_offset + actual_sh[i].sh_size))


        # adding each sh to the ELF
        for i in range(selph.Elf64_Ehdr.e_shnum):
            buff += selph.Elf64_Shdr[i].save()

        open(output_location, "wb").write(buff + b"\n")
        print(good("file saved to : {}".format(output_location)))
