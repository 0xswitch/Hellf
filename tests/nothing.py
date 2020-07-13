from Hellf import ELF
from sys import argv

e = ELF(argv[1])
e.save(argv[2])
