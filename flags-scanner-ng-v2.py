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
import libproducer
from six.moves import cStringIO
import traceback

try:
    import libarchive
except ImportError:
    print("Please install python-libarchive package.")
    sys.exit(-1)

try:
    import pyrpm
except ImportError, exc:
    print(exc)
    print("Please install pyrpm package")
    sys.exit(-1)

import os
import stat
import multiprocessing
import threading

# global stuff
debug_packages = {}
shove = Shove('sqlite:///dump.db')
data = {}
lock = threading.Lock()


def debuginfo_parser(adebug_package, filename):
    """
    return the contents of filename
    """
    try:
        dfd = open(adebug_package, "rb")
        da = libarchive.Archive(dfd)
        for entry in da:
            size = entry.size

            # skip 0 byte files only, size can be 0 due to compression also!
            if size == 0:
                continue

            # skip directories
            if stat.S_ISDIR(entry.mode):
                continue

            # .dwz stuff is special
            if filename == "dwz" and \
                    entry.pathname.startswith("./usr/lib/debug/.dwz/"):
                data = da.read(entry.size)
                da.close()
                dfd.close()
                return cStringIO(data)
            elif entry.pathname.endswith(filename):
                data = da.read(entry.size)
                da.close()
                dfd.close()
                return cStringIO(data)
    except Exception, exc:
        print(adebug_package, str(exc))
        traceback.print_exc()

results = []


def analyze(rpmfile):
    """Analyse single RPM file"""

    if not os.path.exists(rpmfile):
        print("%s doesn't exists!" % rpmfile)
        return

    if rpmfile.endswith(".src.rpm") or not rpmfile.endswith(".rpm"):
        print("skipping %s" % os.path.basename(rpmfile))
        return

    try:
        r = pyrpm.RpmPackage(pyrpm.rpmconfig, rpmfile, verify=None,
                             hdronly=None, db=None)

        r.read(tags=pyrpm.rpmconfig.resolvertags)
        # for k in r:
        #    if k in pyrpm.rpmconfig.resolvertags:
        #        print("%s: %s" % (k, r[k]))

    except Exception, exc:
        print(rpmfile, str(exc))
        return

    # create lookup dictionary
    # nvr = h[rpm.RPMTAG_NVR]
    srpm = r["sourcerpm"]
    # print(srpm, rpmfile)

    r.close()
    found = re.match("(.*)-.*-.*", srpm)
    if not found:
        print("regexp failed ;(", srpm)
        return
    package = found.groups()[0]
    debug_package = package + "-debuginfo-"
    package = r["name"]

    output = {}
    output["package"] = package
    output["build"] = os.path.basename(rpmfile)
    output["files"] = []
    # output["nvr"] = nvr

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
            if a.read(4).startswith(b'\x7fELF'):
                ELFs.append(entry.pathname)
        except:
                pass

    if not ELFs:
        a.close()  # prevent handle leak!
        fd.close()
        return

    # find the corresponding debuginfo RPM
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

    # del ELFs
    # return {"build": rpmfile}, rpmfile

    # create a lookup table for the files in debuginfo RPM
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

    # get the .dwz content for this RPM
    dwz = debuginfo_parser(adebug_package, "dwz")

    # locate the correct corresponding ".debug" file
    for ELF in ELFs:
        fileinfo = {}
        found = False
        for k, v in dac.items():  # lookup in our debuginfo dictionary
            if k.endswith(os.path.basename(ELF + ".debug")):
                found = k
                break

        if not found:
            print("[-]", output["build"], "is missing debug file for", ELF)
            continue

        # get the .debug content
        try:
            debug = debuginfo_parser(adebug_package, found)
            producers = libproducer.process_file(debug, dwz, fast=False)
            fileinfo[ELF] = producers
            debug.close()
        except Exception, exc:
            debug.close()
            traceback.print_exc()

        for producer in producers:
            if "-fstack-protector-strong" not in producer and not \
                    "-fstack-protector-all" in producer:
                    print("%s,%s,%s,not using >= -fstack-protector-strong" %
                          (output["package"], os.path.basename(rpmfile),
                           ELF.lstrip(".")))

        if not producers:
            print("%s,%s" % (output["package"], output["build"]),
                  "is missing producer information for", ELF)
        if len(producers) > 1:
            print("%s,%s" % (output["package"], output["build"]),
                  "has MULTIPLE producers for", ELF)

        output["files"].append(fileinfo)

    dwz.close()
    return output, rpmfile


def output_callback(result):
    with lock:
        if result:
            result, rpmfile = result
            shove[result["build"]] = result
            results.append(rpmfile)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: %s <path to RPM files>\n" % sys.argv[0])
        sys.exit(-1)

    path = sys.argv[1]

    # make a list of all debuginfo packages
    for (path, _, files) in os.walk(path):
        for fname in files:
            # is this a "debuginfo" package?
            if "-debuginfo-" in fname:
                debug_packages[fname] = os.path.abspath(os.path.join(path,
                                                                     fname))

    p = multiprocessing.Pool(4)
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
            for ready in results:  # prevent FAST queue growth!
                try:
                    outputmap[ready].wait()
                    del outputmap[ready]
                except:
                    pass
    p.close()
    p.join()

if __name__ == "__main__":
    main()
