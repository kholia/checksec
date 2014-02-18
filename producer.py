#!/usr/bin/env python
#
# Modified by Dhiru Kholia (dhiru@openwall.com) for Fedora project in January
# of 2014. This program is "inspired" by dwarf_producer.c program witten by
# mjw.
#
#-----------------------------------------------------------------------------
# elftools example: dwarf_die_tree.py
#
# In the .debug_info section, Dwarf Information Entries (DIEs) form a tree.
# pyelftools provides easy access to this tree, as demonstrated here.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-----------------------------------------------------------------------------
#
# https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
# https://fedoraproject.org/wiki/Releases/FeatureBuildId
# http://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
# http://www.technovelty.org/code/separate-debug-info.html
#
# objdump -s -j .gnu_debuglink libtest.so

from __future__ import print_function
import sys
import os
# from six.moves import cStringIO
import binascii

try:
    # from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile
    # from elftools.elf.sections import SymbolTableSection
    from elftools.common.py3compat import bytes2str
    # from elftools.elf.constants import P_FLAGS
    # from elftools.elf.dynamic import DynamicSection
except ImportError as exc:
    print(str(exc), file=sys.stderr)
    print("""\n[-] Please install pyelftools, run "pip install pyelftools" """,
          file=sys.stderr)
    sys.exit(-1)


# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']


def get_dwz(path, offset):
    with open(path, "rb") as f:
        elffile = ELFFile(f)

        for section in elffile.iter_sections():
            name = bytes2str(section.name)
            if name == ".debug_str":
                data = section.data()
                end = data[offset:].find(b"\x00")
                return data[offset:offset + end]


def get_producer(path):
    with open(path, "rb") as f:
        elffile = ELFFile(f)
        dwarfinfo = elffile.get_dwarf_info()

        for CU in dwarfinfo.iter_CUs():
            # DWARFInfo allows to iterate over the compile units
            # contained in the .debug_info section. CU is a CompileUnit
            # object, with some computed attributes (such as its offset
            # in the section) and a header which conforms to the DWARF
            # standard. The access to header elements is, as usual, via
            # item-lookup.
            # print('  Found a compile unit at offset %s, length %s' % (
            #    CU.cu_offset, CU['unit_length']))

            # Start with the top DIE, the root for this CU's DIE tree
            top_DIE = CU.get_top_DIE()
            try:
                attrs = top_DIE.attributes['DW_AT_producer']
                if attrs.form == 'DW_FORM_GNU_strp_alt':
                    # DWARF extensions elfutils recognizes/supports are
                    # described at,
                    #
                    # https://fedorahosted.org/elfutils/wiki/DwarfExtensions
                    #
                    # You can find the alt dwz file by reading the
                    # .gnu_debugaltlink section. Which contains a file name
                    # followed by the build-id of the dwz file. The build-id
                    # symlink will point at the /usr/lib/debug/.dwz/ file.
                    #
                    # export nm=".gnu_debugaltlink"
                    # objdump -s -j $nm /usr/lib/debug/.build-id/XY/34...debug
                    # print("DWZ has the string!")
                    #
                    # DW_FORM_GNU_ref_alt is like DW_FORM_ref, but it refers to
                    # an offset in the .dwz file, not in the main file.
                    # DW_FORM_GNU_strp_alt is like DW_FORM_strp, but it refers
                    # to a string in the .dwz file, not in the main file.
                    for section in elffile.iter_sections():
                        name = bytes2str(section.name)
                        if name == ".gnu_debugaltlink":
                            data = section.data()
                            fdata = data[0:data.find(b"\x00")]
                            i = fdata.find(".dwz/")
                            rpath = os.path.join("/usr/lib/debug/",
                                                 fdata[i:].decode("utf-8"))
                            # offset in alternate (.dwz/...)'s .debug_str"
                            return get_dwz(rpath, offset=attrs.value)
                elif attrs.form == 'DW_FORM_strp':  # lucky ;)
                    return attrs.value
                else:
                    assert 0
            except:
                pass


def process_file(filename):
    # print('Processing file:', filename)

    debug_paths = []
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            for section in elffile.iter_sections():
                name = bytes2str(section.name)
                # print(name)

                # first try to find ".note.gnu.build-id" in ELF itself
                # uint32 name_size; /* size of the name */
                # uint32 hash_size; /* size of the hash */
                # uint32 identifier; /* NT_GNU_BUILD_ID == 0x3 */
                # char   name[name_size]; /* the name "GNU" */
                # char   hash[hash_size]; /* the hash */
                #
                # objdump -s -j .note.gnu.build-id /usr/bin/openssl
                if name == ".note.gnu.build-id":
                    data = section.data()
                    hash = data[16:]
                    value = binascii.hexlify(hash).decode("ascii")
                    # print(value)
                    # a value of "0834ce567a2d57deed6706e28fa29225cf043e16"
                    # implies that we will have a path which looks like,
                    # /usr/lib/debug/.build-id/08/34ce5...25cf043e16.debug
                    path = os.path.join(value[0:2], value[2:] + ".debug")
                    # print(path)
                    debug_paths.append(path)
                # A filename, with any leading directory components removed,
                # followed by a zero byte, zero to three bytes of padding, as
                # needed to reach the next four-byte boundary within the
                # section, and a four-byte CRC checksum, stored in the same
                # endianness used for the executable file itself.
                #
                # objdump -s -j .gnu_debuglink /usr/bin/openssl
                if name == ".gnu_debuglink":
                    data = section.data()
                    fdata = data[0:data.find(b"\x00")]
                    debug_paths.append(fdata.decode("utf-8"))
        else:
            # this file itself has the DWARF information, must be my lucky day!
            get_producer(filename)

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        for path in debug_paths:
            # So, for example, suppose you ask gdb to debug /usr/bin/ls, which
            # has a debug link that specifies the file ls.debug, and a build ID
            # whose value in hex is abcdef1234. If the list of the global debug
            # directories includes /usr/lib/debug, then gdb will look for the
            # following debug information files, in the indicated order:
            #
            # /usr/lib/debug/.build-id/ab/cdef1234.debug
            # /usr/bin/ls.debug
            # /usr/bin/.debug/ls.debug
            # /usr/lib/debug/usr/bin/ls.debug.

            rpath = os.path.join("/usr/lib/debug/.build-id", path)
            if os.path.isfile(rpath):
                producer = get_producer(rpath)  # got producer, is one enough?
                if producer:
                    print(producer)
                    continue

            # `cwd` + "/usr/lib/debug/.build-id" is our hack ;)
            debug_prefixes = ["/usr/lib/debug/.build-id/", "/usr/bin/",
                              "/usr/lib/debug/usr/bin/"]

            for prefix in debug_prefixes:
                rpath = os.path.join(prefix, path)
                if os.path.isfile(rpath):
                    get_producer(rpath)


if __name__ == '__main__':
    for filename in sys.argv[1:]:
        process_file(filename)
