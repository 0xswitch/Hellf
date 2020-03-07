## how to get whole size of binary

# total += pht_size
#
# for i in range(len(selph.Elf64_Shdr)):
#     if i != selph.Elf64_Ehdr.e_shnum - 1:
#         if selph.Elf64_Shdr[i].sh_type != 0x00: # section 0, exist but no size no address, the fuck.
#             nb = selph.Elf64_Shdr[i + 1].sh_offset - selph.Elf64_Shdr[i].sh_offset
#
#             print(selph.Elf64_Shdr[i].sh_name, hex(selph.Elf64_Shdr[i].sh_offset), hex(selph.Elf64_Shdr[i].sh_offset +nb), nb)
#             print(len(selph.Elf64_Shdr[i].data))
#
#             total += nb
#     else:
#         print(hex(selph.Elf64_Ehdr.e_shoff - selph.Elf64_Shdr[i].sh_offset))
#         total += selph.Elf64_Ehdr.e_shoff - selph.Elf64_Shdr[i].sh_offset
#
# total += sht_size
# print(total, hex(total))
