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


def get_dwz(dwz, offset):
    elffile = ELFFile(dwz)

    for section in elffile.iter_sections():
        name = bytes2str(section.name)
        if name == ".debug_str":
            data = section.data()
            end = data[offset:].find(b"\x00")
            return data[offset:offset + end]


def get_producer(debugfile, dwzfile, fast):
    elffile = ELFFile(debugfile)
    dwarfinfo = elffile.get_dwarf_info()

    producers = set()

    for CU in dwarfinfo.iter_CUs():
        # Start with the top DIE, the root for this CU's DIE tree
        top_DIE = CU.get_top_DIE()
        try:
            attrs = top_DIE.attributes['DW_AT_producer']
            if attrs.form == 'DW_FORM_GNU_strp_alt':
                producers.add(get_dwz(dwzfile, offset=attrs.value))
            elif attrs.form == 'DW_FORM_strp':  # lucky ;)
                producers.add(attrs.value)
            else:
                print(attrs.form)
            if fast:  # one producer is enough ;(
                break
        except:
            pass

    return producers


def process_file(debugfile, dwzfile, fast=False):
    elffile = ELFFile(debugfile)

    if not elffile.has_dwarf_info():
        assert 0
    else:
        # this file itself has the DWARF information, must be my lucky day!
        return get_producer(debugfile, dwzfile, fast)
