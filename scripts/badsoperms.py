#!/usr/bin/env python

from checksec import process_file, Elf
from elftools.common.exceptions import ELFError

import sys
import cStringIO

try:
    import libarchive
except ImportError:
    print >> sys.stderr, "Please install python-libarchive from PyPI"
    sys.exit(-1)

try:
    import rpm
except ImportError:
    print >> sys.stderr, "Please install rpm-python package"
    sys.exit(-1)

import os
import json
import stat
import multiprocessing
import threading
from collections import defaultdict

# global stuff
data = {}
lock = threading.Lock()

def analyze(rpmfile, show_errors=False, opformat="json"):
    """Analyse single RPM file"""
    if not os.path.exists(rpmfile):
        print >> sys.stderr, "%s doesn't exists!" % rpmfile
        return

    if not rpmfile.endswith(".rpm"):
        print >> sys.stderr, "skipping %s " % rpmfile
        return

    try:
        a = libarchive.Archive(rpmfile)
    except Exception, exc:
        print >> sys.stderr, rpmfile, str(exc)
        return

    try:
        ts = rpm.TransactionSet()
        ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES)
        fd = os.open(rpmfile, os.O_RDONLY)
        h = ts.hdrFromFdno(fd)
        os.close(fd)
    except Exception, exc:
        print >> sys.stderr, rpmfile, str(exc)
        return

    for entry in a:
        directory = False
        size = entry.size

        if not entry.pathname.endswith(".so"):
            continue

        # print entry.pathname
        # check for executable flag
        if (entry.mode & 0111):
            print package, entry.pathname

    a.close()


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


def output_callback(result):
    pass

def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <path to RPM files> " \
            "[output format (csv / json)] [existing JSON file]\n" \
            % sys.argv[0])
        sys.exit(-1)

    path = sys.argv[1]

    if (len(sys.argv) > 2):
        opformat = sys.argv[2]
    else:
        opformat = "csv"

    parallel = True
    # parallel = False
    if parallel:
        p = multiprocessing.Pool(2) # FIXME add autodetection?

    # pruning code to make analysis faster
    if (len(sys.argv) > 3):
        with open(sys.argv[3]) as f:
            for line in f.readlines():
                line = line.rstrip()
                try:
                    build = json.loads(line)
                    data[build["build"]] = build
                except Exception as exc:
                    print(str(exc))
                    sys.exit(1)

    outputmap = {}
    if(os.path.isfile(path)):
        sys.stderr.write("Analyzing %s ...\n" % path)
        out = analyze(path, opformat=opformat)
    else:
        for (path, _, files) in os.walk(path):
            for fname in files:
                rpmfile = os.path.join(path, fname)
                #if os.path.basename(rpmfile) in data:
                    # print >> sys.stderr, "Skipping", rpmfile
                #    pass
                if parallel:
                    outputmap[rpmfile] = p.apply_async(analyze,
                            (rpmfile, False, opformat),
                            callback = output_callback)
                else:
                    out = analyze(path, opformat=opformat)

    if parallel:
        p.close()
        p.join()

if __name__ == "__main__":
    main()
    # profile_main()
