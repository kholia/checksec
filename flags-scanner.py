#!/usr/bin/env python

from __future__ import print_function

"""Fast RPM analysis tool"""

# Installation
#
# yum install python-shove python-sqlalchemy python-pyelftools \
#       python-libarchive

import sys
from shove import Shove
import re
import subprocess

try:
    import libarchive
except ImportError:
    print("Please install python-libarchive package.")
    sys.exit(-1)

try:
    import rpm
except ImportError, exc:
    print(exc)
    print("Please install rpm-python package")
    sys.exit(-1)

import os
import stat
import multiprocessing
import threading


# global stuff
debug_packages = {}
RAMDISK_path = "RAMDISK"
dwarf_producer_binary = None
shove = Shove('sqlite:///dump.db')
data = {}
lock = threading.Lock()


def analyze(rpmfile):
    """Analyse single RPM file"""

    if not os.path.exists(rpmfile):
        print("%s doesn't exists!" % rpmfile)
        return

    # print(rpmfile)

    if rpmfile.endswith(".src.rpm") or not rpmfile.endswith(".rpm"):
        print("skipping %s" % os.path.basename(rpmfile))
        return

    try:
        ts = rpm.TransactionSet()
        ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES)
        fd = os.open(rpmfile, os.O_RDONLY)
        h = ts.hdrFromFdno(fd)
        os.close(fd)
    except Exception, exc:
        print(rpmfile, str(exc))
        return

    # create lookup dictionary
    nvr = h[rpm.RPMTAG_NVR]
    srpm = h[rpm.RPMTAG_SOURCERPM]
    # print(srpm, rpmfile)
    found = re.match("(.*)-.*-.*", srpm)
    if not found:
        print("regexp failed ;(", srpm)
        return
    package = found.groups()[0]
    debug_package = package + "-debuginfo-"
    package = h[rpm.RPMTAG_NAME]
    group = h[rpm.RPMTAG_GROUP]

    output = {}
    output["package"] = package
    output["group"] = group
    output["build"] = os.path.basename(rpmfile)
    output["files"] = []
    output["nvr"] = nvr

    try:
        fd = open(rpmfile, "rb")
        a = libarchive.Archive(fd)
    except Exception, exc:
        print(rpmfile, str(exc))
        return

    # process the binary RPM
    ELFs = []
    for entry in a:
        size = entry.size

        # skip 0 to 4 byte files only, size can be 0 due to compression also!
        if size < 4 and not stat.S_ISDIR(entry.mode):
            continue

        # skip directories
        if stat.S_ISDIR(entry.mode):
            continue

        # check if the "entry" is an ELF file
        try:
            if a.readstream(entry.pathname).read(4).startswith(b'\x7fELF'):
                ELFs.append(entry.pathname)
        except:
                pass

    if not ELFs:
        a.close()  # prevent handle leak!
        fd.close()
        return

    # extract debuginfo RPM to "RAMDISK"
    adebug_package = None
    for _, v in debug_packages.items():
        if re.match(re.escape(debug_package) + "\d", os.path.basename(v)):
            adebug_package = v
            break
    if not adebug_package:
        print('[-] missing "debuginfo" RPM for', output["build"])
        a.close()  # prevent handle leak!
        fd.close()
        return

    try:
        dfd = open(adebug_package, "rb")
        da = libarchive.Archive(dfd)
        dac = {}
    except Exception, exc:
        print(adebug_package, str(exc))
        a.close()  # prevent handle leak!
        fd.close()
        return
    for entry in da:
        size = entry.size

        # skip 0 byte files only, size can be 0 due to compression also!
        if size == 0 and not stat.S_ISDIR(entry.mode):
            continue

        # skip directories
        if stat.S_ISDIR(entry.mode):
            continue

        dac[entry.pathname] = True

    # close all file handles
    a.close()
    fd.close()
    dfd.close()
    da.close()

    # extract debuginfo RPM into "RAMDISK"
    print('[*] extracting "debuginfo" RPM %s for %s' % (adebug_package,
                                                        output["build"]))

    p = subprocess.Popen("rpm2cpio %s | cpio -idmuv" % adebug_package,
                         shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         cwd=RAMDISK_path, close_fds=True)
    p.communicate()

    # locate the correct corresponding ".debug" file
    for ELF in ELFs:
        fileinfo = {}
        found = False
        for k, v in dac.items():
            if k.endswith(os.path.basename(ELF + ".debug")):
                found = k
                break

        if not found:
            print("[-]", output["build"], "is missing debug file for", ELF)
            continue

        debug_path = os.path.join(RAMDISK_path,
                                  os.path.dirname(found).lstrip("./"))

        p = subprocess.Popen("%s %s" % (dwarf_producer_binary,
                                        os.path.basename(found)),
                             cwd=debug_path, shell=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             close_fds=True)

        producers, _ = p.communicate()
        fileinfo[ELF] = producers.strip()
        if "-fstack-protector-strong" not in producers and \
                not "-fstack-protector-all" in producers:
            print("%s -> %s is not using >= -fstack-protector-strong" %
                  (rpmfile, ELF))

        if not producers:
            print("[!]", output["build"],
                  "is missing producer information for", ELF)
            continue

        output["files"].append(fileinfo)

    # print(output)
    return output


def output_callback(result):
    with lock:
        if result:
            # print(result)
            shove[result["build"]] = result
            # print(result)
        else:
            pass


def profile_main():
    # Run 'main' redirecting its output to readelfout.txt
    # Saves profiling information in readelf.profile
    PROFFILE = 'readelf.profile'
    import cProfile
    cProfile.run('main()', PROFFILE)

    # Dig in some profiling stats
    import pstats
    p = pstats.Stats(PROFFILE)
    p.sort_stats('cumulative').print_stats(200)


def main():
    global dwarf_producer_binary
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: %s <path to RPM files>\n" % sys.argv[0])
        sys.exit(-1)

    # locate dwarf_producer binary
    dwarf_producer_binary = os.path.realpath("./dwarf_producer")

    # make "RAMDISK" folder
    try:
        os.mkdir("RAMDISK")
    except:
        pass

    path = sys.argv[1]

    for (path, _, files) in os.walk(path):
        for fname in files:
            # is this a "debuginfo" package?
            if "-debuginfo-" in fname:
                debug_packages[fname] = os.path.abspath(os.path.join(path,
                                                                     fname))

    p = multiprocessing.Pool(8)
    outputmap = {}

    for (path, _, files) in os.walk(sys.argv[1]):
        for fname in files:
            # is this a "debuginfo" package?
            if "-debuginfo-" in fname:
                continue
            rpmfile = os.path.abspath(os.path.join(path, fname))
            if not rpmfile.endswith(".rpm"):
                continue
            outputmap[rpmfile] = p.apply_async(
                analyze,
                [rpmfile],
                callback=output_callback)
    p.close()
    p.join()

if __name__ == "__main__":
    # profile_main()
    main()
