#!/usr/bin/env python

"""Fast RPM analysis tool"""

from checksec import process_file, Elf
from elftools.common.exceptions import ELFError

import sys
from six.moves import cStringIO

try:
    import libarchive
except ImportError:
    print("Please install python-libarchive package.")
    sys.exit(-1)

try:
    import rpm
except ImportError as exc:
    print(exc)
    print("Please install rpm-python package")
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
        # print >> sys.stderr, "skipping %s" % os.path.basename(rpmfile)
        return

    try:
        a = libarchive.Archive(rpmfile)
    except Exception as exc:
        print >> sys.stderr, rpmfile, str(exc)
        return

    try:
        ts = rpm.TransactionSet()
        ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES)
        fd = os.open(rpmfile, os.O_RDONLY)
        h = ts.hdrFromFdno(fd)
        os.close(fd)
    except Exception as exc:
        print >> sys.stderr, rpmfile, str(exc)
        return

    # create lookup dictionary
    # print dir(h)
    # print dir(rpm)
    nvr = h[rpm.RPMTAG_NVR]
    package = h[rpm.RPMTAG_NAME]
    group = h[rpm.RPMTAG_GROUP]
    caps = h[rpm.RPMTAG_FILECAPS]
    names = h['FILENAMES']
    groups = h[rpm.RPMTAG_FILEGROUPNAME]
    users = h[rpm.RPMTAG_FILEUSERNAME]
    lookup = defaultdict(list)
    for n, u, g in zip(names, users, groups):
        lookup[n].append((u, g))

    filecaps = []
    for i, cap in enumerate(caps):
        if cap:
            filecaps.append([names[i], cap])

    pols = []
    lines = ""
    output = {}
    output["package"] = package
    output["group"] = group
    output["build"] = os.path.basename(rpmfile)
    output["files"] = []
    output["daemon"] = False
    output["nvr"] = nvr
    output["filecaps"] = filecaps
    output["polkit"] = False
    output["caps"] = False
    output["pols"] = pols

    if filecaps:
        output["caps"] = True

    flag = False

    for entry in a:
        directory = False
        size = entry.size
        # polkit checks, "startswith" is better but ...
        if "/etc/polkit" in entry.pathname or \
           "/usr/share/PolicyKit" in entry.pathname or \
           "/usr/share/polkit-1" in entry.pathname:
            pols.append(entry.pathname)
            output["polkit"] = True

        # check if package is a daemon
        if "/etc/rc.d/init.d" in entry.pathname or \
           "/lib/systemd" in entry.pathname:
            output["daemon"] = True

        # skip 0 byte files only
        # NOTE: size can be 0 due to compression also!
        if size == 0 and not stat.S_ISDIR(entry.mode):
            continue

        # we are only interested in particular kind of directories
        if stat.S_ISDIR(entry.mode):
            if not ((entry.mode & stat.S_ISUID) or
                    (stat.S_ISGID & entry.mode)):
                continue
            else:
                flag = True
                directory = True

        # check for executable flag
        # if not (entry.mode & 0111):
        #    continue

        # always report setxid files
        if ((entry.mode & stat.S_ISUID) or (stat.S_ISGID & entry.mode)):
            flag = True

        # skip library files
        filename = entry.pathname.lstrip(".")
        # if not flag and (("lib" in filename and ".so" in filename) or \
        #   filename.endswith(".so")):
        #   continue

        try:
            contents = a.read(size)
        except Exception:
            continue

        # invoke checksec only on files
        returncode = -1
        if not directory:
            try:
                fh = cStringIO(contents)
                elf = Elf(fh)
                if opformat == "json":
                    out = process_file(elf, deps=True)
                    # polkit check 2
                    if "polkit" in out:
                        output["polkit"] = True
                else:
                    out = process_file(elf)
                dataline = "%s,%s,%s,mode=%s,%s" % (package,
                                                    os.path.basename(rpmfile),
                                                    filename, oct(entry.mode),
                                                    out)
                returncode = 0
            except ELFError as exc:
                if show_errors:
                    print >> sys.stderr, "%s,%s,Not an ELF binary" % \
                        (filename, str(exc))
                continue
            except IOError as exc:
                if show_errors:
                    print >> sys.stderr, "%s,%s,Not an ELF binary" % \
                        (filename, str(exc))
                continue
        if flag or returncode == 0:
            # populate fileinfo object
            fileinfo = {}
            fileinfo["name"] = filename
            fileinfo["size"] = entry.size
            fileinfo["mode"] = entry.mode
            fileinfo["user"], fileinfo["group"] = lookup[filename][0]
            if directory:
                fileinfo["directory"] = directory
            output["files"].append(fileinfo)

        if returncode == 0 and opformat == "csv":
            lines = lines + dataline + "\n"
        else:
            # print >> sys.stderr, dataline
            pass
        if returncode == 0 and opformat == "json":
            try:
                for kvp in out.split(","):
                    key, value = kvp.split("=")
                    fileinfo[key] = value
            except Exception:
                pass
    a.close()

    if opformat == "json":
        return json.dumps(output)
    else:
        return lines.rstrip()


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
    with lock:
        if result:
            print(result)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <path to RPM files> "
                    "[output format (csv / json)] [existing JSON file]\n"
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
        p = multiprocessing.Pool(5)  # FIXME add autodetection?

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
        if out:
            print(out)
    else:
        for (path, _, files) in os.walk(path):
            for fname in files:
                rpmfile = os.path.join(path, fname)
                if "-debuginfo-" in rpmfile or rpmfile.endswith(".drpm"):
                    continue
                #if os.path.basename(rpmfile) in data:
                    # print >> sys.stderr, "Skipping", rpmfile
                #    pass
                if parallel:
                    outputmap[rpmfile] = p.apply_async(analyze,
                            (rpmfile, False, opformat),
                            callback=output_callback)
                else:
                    out = analyze(path, opformat=opformat)
                    if out:
                        print(out)

    if parallel:
        p.close()
        p.join()

if __name__ == "__main__":
    main()
    # profile_main()
