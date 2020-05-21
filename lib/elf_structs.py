import ctypes as c
from collections import OrderedDict
from struct import unpack_from, pack
from binascii import hexlify


def typemap(cls):
    """
    wrapper who is incharge of adding _fmt attribute holding the struct format for each field and the struct itself and also the struct size
    """
    struct_fmt = ""
    for t, v in cls._fields_:

        if hasattr(v, "_length_"):
            fmt = str( v._length_) + v._type_._type_
        else:
            fmt = v._type_
        struct_fmt += fmt + " "
        setattr(cls, "_" + t + "_fmt", fmt)

    setattr(cls, "struct_fmt", struct_fmt)
    setattr(cls, "struct_size", c.sizeof(cls))

    return cls


class original_struct_list:

    def save(self):
        return b"".join([i.save() for i in self])


class orginal_struct:

    def __init__(cls, ELF_obj, count=None, next_sh=None):

        if isinstance(cls, Elf64_Ehdr_ST):
            cls.elf_data = ELF_obj.elf_data[:cls.struct_size]
        elif isinstance(cls, Elf64_Phdr_ST):
            cls.elf_data = ELF_obj.elf_data[ELF_obj.Elf64_Ehdr.e_phoff +  Elf64_Phdr_ST.struct_size * count : ELF_obj.Elf64_Ehdr.e_phoff + Elf64_Phdr_ST.struct_size * (count + 1)]

        elif isinstance(cls, Elf64_Shdr_ST):
            cls.elf_data = ELF_obj.elf_data[ ELF_obj.Elf64_Ehdr.e_shoff + Elf64_Shdr_ST.struct_size * (count - 1) : ELF_obj.Elf64_Ehdr.e_shoff +  Elf64_Shdr_ST.struct_size * count]

        for struct_field in cls.fields_names:
            fmt = getattr(cls, "_" + struct_field + "_fmt")
            offset = getattr(cls.__class__, struct_field).offset

            value = unpack_from(fmt, cls.elf_data, bufferoffset:=offset)

            if len(value) == 1:
                value = value[0]

            setattr(cls, struct_field, value)

        # getting data which will be in the Segment described by this segment header
        if isinstance(cls, Elf64_Phdr_ST):
             setattr(cls, "data",ELF_obj.elf_data[cls.p_offset:cls.p_offset+cls.p_filesz])

        #  getting data described by this section headers
        if isinstance(cls, Elf64_Shdr_ST):
            if cls.sh_type not in [0x00, 0x08]: # they do not have space on file only at runtime

                # size = next_sh - cls.sh_offset
                size = cls.sh_size

                setattr(cls, "data", ELF_obj.elf_data[cls.sh_offset:cls.sh_offset + size].rstrip(b"\x00"))
                setattr(cls, "size_padded", size)
            else:
                setattr(cls, "data", b"")
                setattr(cls, "size_padded", 0)


    def __repr__(cls):
        msg =  cls.struct_description + "\n"
        fmt = "  {}:\t{}\n"
        for field in cls.fields_names:

            if hasattr(cls.allowed_fields[field], "_length_"):
                msg += fmt.format(field, " ".join(list(map(hex,getattr(cls, field)))))
            else:
                msg += fmt.format(field, hex(getattr(cls, field)))
        return msg

    def save(cls):
        saved_struct_bytes = b""
        for struct_field in cls.fields_names:
            fmt = getattr(cls, "_" + struct_field + "_fmt")

            if not hasattr(cls.__class__.allowed_fields[struct_field], "_length_"):
                saved_struct_bytes += pack(fmt, getattr(cls, struct_field))
            else:
                saved_struct_bytes += pack(fmt, *getattr(cls, struct_field))
        return saved_struct_bytes#.decode("utf-8")



@typemap
class Elf64_Ehdr_ST(c.Structure, orginal_struct):
    """
    elf header structure
    """

    struct_description = "ELF Header struct"

    # typedef struct
    # {
    #   unsigned char e_ident[EI_NIDENT];     /* Magic number and other info */
    #   Elf64_Half    e_type;                 /* Object file type */
    #   Elf64_Half    e_machine;              /* Architecture */
    #   Elf64_Word    e_version;              /* Object file version */
    #   Elf64_Addr    e_entry;                /* Entry point virtual address */
    #   Elf64_Off     e_phoff;                /* Program header table file offset */
    #   Elf64_Off     e_shoff;                /* Section header table file offset */
    #   Elf64_Word    e_flags;                /* Processor-specific flags */
    #   Elf64_Half    e_ehsize;               /* ELF header size in bytes */
    #   Elf64_Half    e_phentsize;            /* Program header table entry size */
    #   Elf64_Half    e_phnum;                /* Program header table entry count */
    #   Elf64_Half    e_shentsize;            /* Section header table entry size */
    #   Elf64_Half    e_shnum;                /* Section header table entry count */
    #   Elf64_Half    e_shstrndx;             /* Section header string table index */
    # } Elf64_Ehdr;

    allowed_fields = OrderedDict([
    ("e_ident", c.c_ubyte * 16),
    ("e_type", c.c_uint16),
    ("e_machine", c.c_uint16),
    ("e_version", c.c_uint32),
    ("e_entry", c.c_uint64),
    ("e_phoff", c.c_uint64),
    ("e_shoff", c.c_uint64),
    ("e_flags", c.c_uint32),
    ("e_ehsize", c.c_uint16),
    ("e_phentsize", c.c_uint16),
    ("e_phnum", c.c_uint16),
    ("e_shentsize", c.c_uint16),
    ("e_shnum", c.c_uint16),
    ("e_shstrndx", c.c_uint16),
    ])

    fields_names = allowed_fields.keys()

    _fields_ = [(name, size) for name, size in allowed_fields.items()]

    def __init__(self, ELF_obj):
        c.Structure.__init__(self)
        orginal_struct.__init__(self, ELF_obj)



class Elf64_Shdr_LST(list, original_struct_list):

    def __init__(self, ELF_obj):

        t = []

        for i in range(ELF_obj.Elf64_Ehdr.e_shnum, 0, -1):

            if i == ELF_obj.Elf64_Ehdr.e_shnum:
                next_sh = ELF_obj.Elf64_Ehdr.e_shoff
            else:
                next_sh = t[ELF_obj.Elf64_Ehdr.e_shnum - i - 1].sh_offset

            t.append(Elf64_Shdr_ST(ELF_obj, count=i, next_sh=next_sh))

        list.__init__(self, t[::-1])




@typemap
class Elf64_Shdr_ST(c.Structure, orginal_struct):
    """
    sections header structure
    """
    struct_description = "ELF Sections header struct"

    # typedef struct 
    # {
    #   Elf64_Word    sh_name;                /* Section name (string tbl index) */ 4
    #   Elf64_Word    sh_type;                /* Section type */ 4
    #   Elf64_Xword   sh_flags;               /* Section flags */ 8
    #   Elf64_Addr    sh_addr;                /* Section virtual addr at execution */ 8
    #   Elf64_Off     sh_offset;              /* Section file offset */ 8
    #   Elf64_Xword   sh_size;                /* Section size in bytes */ 8
    #   Elf64_Word    sh_link;                /* Link to another section */ 4
    #   Elf64_Word    sh_info;                /* Additional section information */ 4
    #   Elf64_Xword   sh_addralign;           /* Section alignment */ 8
    #   Elf64_Xword   sh_entsize;             /* Entry size if section holds table */ 8
    # } Elf64_Shdr;

    allowed_fields = OrderedDict([
    ("sh_name" , c.c_uint32),
    ("sh_type" , c.c_uint32),
    ("sh_flags" , c.c_uint64),
    ("sh_addr" , c.c_uint64),
    ("sh_offset" , c.c_uint64),
    ("sh_size" , c.c_uint64),
    ("sh_link" , c.c_uint32),
    ("sh_info" , c.c_uint32),
    ("sh_addralign" , c.c_uint64),
    ("sh_entsize" , c.c_uint64)
    ])

    fields_names = allowed_fields.keys()
    _fields_ = [(name, size) for name, size in allowed_fields.items()]

    def __init__(self, ELF_obj=None, count=None, next_sh=None):
        c.Structure.__init__(self)

        # we don't want to have the struct field automatically filled as we filled them ourself
        # getting the Shdr automatically by parsing an ELF
        if count != None and next_sh != None and ELF_obj != None:
            orginal_struct.__init__(self, ELF_obj, count=count, next_sh=next_sh)


class Elf64_Ehdr_LST(list, original_struct_list):

    def __init__(self, ELF_obj):

        list.__init__(self, [ Elf64_Phdr_ST(ELF_obj, i) for i in range(ELF_obj.Elf64_Ehdr.e_phnum)])


@typemap
class Elf64_Phdr_ST(c.Structure, orginal_struct):
    """
    program headers structure
    """
    struct_description = "ELF Program header struct"

    # typedef struct
    # {
    #   Elf64_Word    p_type;                 /* Segment type */
    #   Elf64_Word    p_flags;                /* Segment flags */
    #   Elf64_Off     p_offset;               /* Segment file offset */
    #   Elf64_Addr    p_vaddr;                /* Segment virtual address */
    #   Elf64_Addr    p_paddr;                /* Segment physical address */
    #   Elf64_Xword   p_filesz;               /* Segment size in file */
    #   Elf64_Xword   p_memsz;                /* Segment size in memory */
    #   Elf64_Xword   p_align;                /* Segment alignment */
    # } Elf64_Phdr;
    #

    allowed_fields = OrderedDict([
    ("p_type", c.c_uint32),
    ("p_flags", c.c_uint32),
    ("p_offset", c.c_uint64),
    ("p_vaddr", c.c_uint64),
    ("p_paddr", c.c_uint64),
    ("p_filesz", c.c_uint64),
    ("p_memsz", c.c_uint64),
    ("p_align", c.c_uint64),
    ])

    fields_names = allowed_fields.keys()
    _fields_ = [(name, size) for name, size in allowed_fields.items()]

    def __init__(self, ELF_obj, count):
        c.Structure.__init__(self)
        orginal_struct.__init__(self, ELF_obj, count=count)


# /* Types for signed and unsigned 32-bit quantities.  */
# typedef uint32_t Elf32_Word;
# typedef int32_t  Elf32_Sword;
# typedef uint32_t Elf64_Word;
# typedef int32_t  Elf64_Sword;
#
# /* Types for signed and unsigned 64-bit quantities.  */
# typedef uint64_t Elf32_Xword;
# typedef int64_t  Elf32_Sxword;
# typedef uint64_t Elf64_Xword;
# typedef int64_t  Elf64_Sxword;
#
# /* Type of addresses.  */
# typedef uint32_t Elf32_Addr;
# typedef uint64_t Elf64_Addr;
#
# /* Type of file offsets.  */
# typedef uint32_t Elf32_Off;
# typedef uint64_t Elf64_Off;
#
# /* Type for section indices, which are 16-bit quantities.  */
# typedef uint16_t Elf32_Section;
# typedef uint16_t Elf64_Section;
#
# /* Type for version symbol information.  */
# typedef Elf32_Half Elf32_Versym;
# typedef Elf64_Half Elf64_Versym;
