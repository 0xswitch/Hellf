#!/usr/bin/python3
from Hellf.lib.elf_structs import *

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
        for sh in selph.Elf64_Shdr:
            sh_name = selph.Elf64_Shdr[-1].data[sh.sh_name:].split(b"\x00")[0].decode("utf-8") # last sh describe .shstrtab which contains sections names
            if sh_name == name:
                return sh

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

        # adding all data described by sections to the ELF
        for i in range(selph.Elf64_Ehdr.e_shnum):

            # if sh data is modified and size less than previous size,
            # we need to pad with \x00 to keep the initial size
            # we need to keep the initial size else the offset for the next sh would change

            # custom section haven't got padded size attribute as sh_size is the real size so skipping this check
            if hasattr(selph.Elf64_Shdr[i], "size_padded"):

                if len(selph.Elf64_Shdr[i].data) != selph.Elf64_Shdr[i].size_padded:
                    selph.Elf64_Shdr[i].data += b"\x00" * (selph.Elf64_Shdr[i].size_padded - len(selph.Elf64_Shdr[i].data))

            buff += selph.Elf64_Shdr[i].data


        # adding each sh to the ELF
        for i in range(selph.Elf64_Ehdr.e_shnum):
            buff += selph.Elf64_Shdr[i].save()

        open(output_location, "wb").write(buff + b"\n")
        print(good("file saved to : {}".format(output_location)))
