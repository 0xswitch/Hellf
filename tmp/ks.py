from keystone import *
from ctypes import c_char

ks = Ks(KS_ARCH_X86, KS_MODE_64)
ks.syntax = KS_OPT_SYNTAX_NASM

sc = open("./src/stub.s", "r").read()
# print("\n".join(sc))

asm = ks.asm(sc)[0]

print(len(list(map(hex,asm))))

open("/tmp/sc", "wb").write((c_char * len(asm)).from_buffer(bytearray(asm)).raw)
