#!/usr/bin/env python

from __future__ import print_function

import sys
import re
from six.moves import cStringIO
import six

try:
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.common.py3compat import bytes2str
    from elftools.elf.constants import P_FLAGS
    from elftools.elf.dynamic import DynamicSection
except ImportError as exc:
    print(str(exc), file=sys.stderr)
    print("""\n[-] Please install python-pyelftools package""",
          file=sys.stderr)
    sys.exit(-1)

# http://people.redhat.com/sgrubb/security/find-elf4tmp
TMP_FUNCTIONS = set(["^mkstemp",  "^tempnam", "^tmpfile"])

# XXX add more APR and other common patterns
LOCAL_PATTERNS = set([
    "^connect$", "^listen$", "^accept$", "^accept4$",
    "^apr_socket_accept$", "PR_Accept", "PR_Listen",
    "^getpeername", "^SSL_accept"])

IP_PATTERNS = set([
    "getaddrinfo", "getnameinfo", "getservent", "getservbyname",
    "getservbyport", "gethostbyname", "gethostbyname2",
    "gethostbyaddr", "gethostbyaddr2", "apr_getnameinfo",
    "PR_GetAddrInfoByName"])

# FORTIFY_SOURCE checklist
UNSAFE_FUNCTIONS = set([
    "asprintf",        "mbsnrtowcs",       "snprintf",
    "vsyslog",         "confstr",          "mbsrtowcs",
    "sprintf",         "vwprintf",         "dprint",
    "mbstowcs",        "stpcpy",           "wcpcpy",
    "fgets",           "memcpy",           "stpncpy",
    "wcpncpy",         "fgets_unlocked",   "memmove",
    "strcat",          "wcrtomb",          "fgetws",
    "mempcpy",         "strcpy",           "wcscat",
    "fgetws_unlocked", "memset",           "strncat",
    "wcscpy",          "fprintf",          "obstack_printf",
    "strncpy",         "wcsncat",          "fread",
    "obstack_vprintf", "swprintf",         "wcsncpy",
    "fread_unlocked",  "pread",            "syslog",
    "wcsnrtombs",      "fwprintf",         "pread64",
    "ttyname_r",       "wcsrtombs",        "getcwd",
    "printf",          "vasprintf",        "wcstombs",
    "getdomainname",   "ptsname_r",        "vdprintf",
    "wctomb",          "getgroups",        "read",
    "vfprintf",        "wmemcpy",          "gethostname",
    "readlink",        "vfwprintf",        "wmemmove",
    "getlogin_r",      "readlinkati",      "vprintf",
    "wmempcpy",        "gets",             "realpath",
    "vsnprintf",       "wmemset",          "getwd",
    "recv",            "vsprintf",         "wprintf"
    "longjmp",         "recvfrom",         "vswprintf"])

STACK_CHK = set(["__stack_chk_fail", "__stack_smash_handler"])


class Elf(object):
    def __init__(self, fileobj):
        self.elffile = ELFFile(fileobj)
        self.output = sys.stdout

    # our code starts here :-)

    def network(self):
        ret = "None"
        for section in self.elffile.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            if section['sh_entsize'] == 0:
                print(
                    "\nSymbol table '%s' has a sh_entsize "
                    "of zero!" % (bytes2str(section.name)), file=sys.stderr)
                continue
            for _, symbol in enumerate(section.iter_symbols()):
                # first match IP_PATTERNS
                for pattern in IP_PATTERNS:
                    if re.match(pattern, bytes2str(symbol.name)):
                        return "network-ip"
                # then match LOCAL_PATTERNS
                for pattern in LOCAL_PATTERNS:
                    if re.match(pattern, bytes2str(symbol.name)):
                        ret = "network-local"
                        break
        return ret

    def _strings(self):
        stream = self.elffile.stream
        epos = stream.tell()
        stream.seek(0, 0)
        data = stream.read()
        stream.seek(epos, 0)

        ret = []

        # XXX avoid calling eu-strings
        import subprocess
        p = subprocess.Popen(
            "eu-strings", shell=True, stdin=subprocess.PIPE,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        out = p.communicate(input=data)[0]

        for line in out.splitlines():
            if re.match(b"^/tmp/.+", line) and "XXX" not in line:
                ret.append(line)

        return ret

    def tempstuff(self):
        tmp_strings = self._strings()

        # if there are no /tmp references, just return
        if len(tmp_strings) == 0:
            return "None"

        for section in self.elffile.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            if section['sh_entsize'] == 0:
                print(
                    "\nSymbol table '%s' has a sh_entsize "
                    "of zero!" % (bytes2str(section.name)), file=sys.stderr)
                continue
            for _, symbol in enumerate(section.iter_symbols()):
                for pattern in TMP_FUNCTIONS:
                    if re.match(pattern, bytes2str(symbol.name)):

                        return "None"

        return "$".join(tmp_strings)

    # XXX implement this
    def chroot_without_chdir(self):
        """
        Check for apps that use chroot(2) without using chdir(2).

        Inspired by http://people.redhat.com/sgrubb/security/find-chroot

        """
        pass

    def fortify(self):
        """
        Check if source code was compiled with FORTIFY_SOURCE.

        Enabled : no unsafe functions were found OR all were translated to _chk versions
        Partial : unprotected unsafe functions were found

        TODO
        ====

        * Print summary report like checksec.sh does

        * Drop CSV output support (it is too restrictive)

        * "addr2line" like feature for unprotected unsafe functions

        """
        unsafe_list = []

        for section in self.elffile.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            if section['sh_entsize'] == 0:
                print(
                    "\nSymbol table '%s' has a sh_entsize "
                    "of zero!" % (bytes2str(section.name)), file=sys.stderr)
                continue
            for _, symbol in enumerate(section.iter_symbols()):
                for pattern in UNSAFE_FUNCTIONS:
                    if re.match(pattern + "$", bytes2str(symbol.name)):
                        unsafe_list.append(bytes2str(symbol.name))

        if len(unsafe_list) == 0:
            return "Enabled"
        else:
            return "Partial$" + "$".join(unsafe_list)


    def canary(self):
        for section in self.elffile.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            if section['sh_entsize'] == 0:
                print(
                    "\nSymbol table '%s' has a sh_entsize "
                    "of zero!" % (bytes2str(section.name)), file=sys.stderr)
                continue
            for _, symbol in enumerate(section.iter_symbols()):
                if bytes2str(symbol.name) in STACK_CHK:
                    return "Enabled"
        return "Disabled"

    def dynamic_tags(self, key="DT_RPATH"):
        for section in self.elffile.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            for tag in section.iter_tags():
                if tag.entry.d_tag == key:
                    return "Enabled"
        return "Disabled"

    def program_headers(self):
        pflags = P_FLAGS()
        if self.elffile.num_segments() == 0:
            # print('There are no program headers in this file.', \
            #      file=sys.stderr)
            return

        found = False
        for segment in self.elffile.iter_segments():
            if re.search("GNU_STACK", str(segment['p_type'])):
                found = True
                if segment['p_flags'] & pflags.PF_X:
                    return "Disabled"
        if found:
            return "Enabled"

        return "Disabled"

    def relro(self):
        if self.elffile.num_segments() == 0:
            # print('There are no program headers in this file.', \
            #      file=sys.stderr)
            return

        have_relro = False
        for segment in self.elffile.iter_segments():
            if re.search("GNU_RELRO", str(segment['p_type'])):
                have_relro = True
                break
        if self.dynamic_tags("DT_BIND_NOW") == "Enabled" and have_relro:
            return "Enabled"
        if have_relro:
            return "Partial"

        return "Disabled"

    def pie(self):
        header = self.elffile.header
        if self.dynamic_tags("EXEC") == "Enabled":
            return "Disabled"
        if "ET_DYN" in header['e_type']:
            if self.dynamic_tags("DT_DEBUG") == "Enabled":
                return "Enabled"
            else:
                return "DSO"
        return "Disabled"

    def getdeps(self):
        deps = []

        if self.elffile.num_segments() == 0:
            return deps

        for segment in self.elffile.iter_segments():
            if re.search("PT_DYNAMIC", str(segment['p_type'])):
                # this file uses dynamic linking, so read the dynamic section
                # and find DT_SONAME tag
                for section in self.elffile.iter_sections():
                    if not isinstance(section, DynamicSection):
                        continue
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == 'DT_NEEDED':
                            deps.append(bytes2str(tag.needed))
                break

        return deps


def process_file(elfo, deps=True):

    output = "NX=%s,CANARY=%s,RELRO=%s,PIE=%s,RPATH=%s,RUNPATH=%s," \
        "FORTIFY=%s,CATEGORY=%s,TEMPPATHS=%s" \
        % (elfo.program_headers(), elfo.canary(), elfo.relro(), elfo.pie(),
            elfo.dynamic_tags("DT_RPATH"), elfo.dynamic_tags("DT_RUNPATH"),
            elfo.fortify(), elfo.network(), elfo.tempstuff())
    if deps:
        output = output + (",DEPS=%s" % '$'.join(elfo.getdeps()))

    return output

if __name__ == "__main__":

    if len(sys.argv) < 2:
        try:
            if six.PY3:
                import io
                sys.stdin = sys.stdin.detach()
                fh = io.BytesIO(sys.stdin.read())
            else:
                fh = cStringIO(sys.stdin.read())
            elf = Elf(fh)

        except ELFError as exc:
            print("%s,Not an ELF binary" % str(exc), file=sys.stderr)
            sys.exit(-1)
        except IOError as exc:
            print("%s,Not an ELF binary" % str(exc), file=sys.stderr)
            sys.exit(-1)

        print(process_file(elf))

    else:
        for i in range(1, len(sys.argv)):
            try:
                filename = sys.argv[i]
                elf = Elf(open(filename, "rb"))
            except ELFError as exc:
                print(
                    "%s,%s,Not an ELF binary" %
                    (filename, str(exc)), file=sys.stderr)
                continue
            except IOError as exc:
                print(
                    "%s,%s,Not an ELF binary" %
                    (filename, str(exc)), file=sys.stderr)
                continue

            print("%s,%s" % (filename, process_file(elf)))
