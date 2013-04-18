import sys

blurb = """
$ python3 virtualenv.py venv-p3
$ source venv-p3/bin/activiate
$ pip install six
$ pip install requests

http://packages.debian.org/sid/python3-chardet

http://packages.debian.org/sid/python3-debian

See http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=506861

http://archive.ubuntu.com/ubuntu/dists/raring/

"""

from checksec import process_file, Elf
from elftools.common.exceptions import ELFError

try:
    from debian.debfile import DebFile
except ImportError as exc:
    print(exc)
    print("Dependencies not met, use following steps!")
    print(blurb)
    sys.exit(-1)

from io import BytesIO
import os
import stat
import json
import multiprocessing

BASE_URL = "http://archive.ubuntu.com/ubuntu/"
database = {}
sections = {}
opformat = "csv"

def analyze(debfile, package="?", group="?", show_errors=False):
    deb = DebFile(filename=debfile)
    tgz = deb.data.tgz()

    if not os.path.exists(debfile):
        # print >> sys.stderr, "%s doesn't exists!" % debfile
        pass

    if not debfile.endswith(".deb"):
        return

    output = {}
    output["package"] = package
    output["group"] = group
    output["build"] = os.path.basename(debfile)
    output["files"] = []
    output["daemon"] = False
    flag = False
    directory = False

    for entry in tgz.getmembers():
        size = entry.size

        # check if package is a daemon
        if "/etc/rc.d/init.d" in entry.name or "/lib/systemd" in entry.name:
            output["daemon"] = True

        # skip 0 byte files only
        if size == 0 and not stat.S_ISDIR(entry.mode):
            continue

        # we are only interested in particular kind of directories
        if stat.S_ISDIR(entry.mode):
            if not ((entry.mode & stat.S_ISUID) or (stat.S_ISGID & entry.mode)):
                continue
            else:
                flag = True
                directory = True

        if not entry.mode & 0o111:
            continue

        # always report setuid files
        if ((entry.mode & stat.S_ISUID) or (stat.S_ISGID & entry.mode)):
            flag = True

        # skip library files
        filename = entry.name.lstrip(".")
        if ("lib" in filename and ".so" in filename) or \
           filename.endswith(".so"):
            continue

        try:
            contents = tgz.extractfile(entry).read()
        except Exception as exc:
            print(exc)

        # invoke checksec
        returncode = -1
        try:
            fh = BytesIO(contents)
            elf = Elf(fh)
            out = process_file(elf)
            returncode = 0
            dataline = "%s,%s,%s,%s" % (package, os.path.basename(debfile),
                                        filename, out)
        except ELFError as exc:
            continue
        except IOError as exc:
            continue

        # print p.returncode, filename
        if returncode == 0 or flag:
            # populate fileinfo object
            fileinfo = {}
            fileinfo["name"] = filename
            fileinfo["size"] = entry.size
            fileinfo["mode"] = entry.mode
            if directory:
                fileinfo["directory"] = directory
            output["files"].append(fileinfo)
        if returncode == 0 and opformat == "csv":
            print(dataline)
        if returncode == 0 and opformat == "json":
            try:
                for kvp in out.rstrip().split(","):
                    key, value = kvp.split("=")
                    fileinfo[key] = value
            except Exception:
                pass

        if opformat == "json":
            print(json.dumps(output, sort_keys=True, indent=4,
                         separators=(',', ': ')))


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
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <path to .deb files> " \
            "[output format (csv / json)] [existing JSON file]\n" \
            % sys.argv[0])
        sys.exit(-1)

    path = sys.argv[1]

    global opformat
    if (len(sys.argv) > 2):
        opformat = sys.argv[2]
    else:
        opformat = "csv"

    parallel = True
    # parallel = False
    if parallel:
        p = multiprocessing.Pool(4)

    output = {}
    if(os.path.isfile(path)):
        sys.stderr.write("Analyzing %s ...\n" % path)
        out = analyze(path)
        if out:
            print(out)
    else:
        for (path, _, files) in os.walk(path):
            for fname in files:
                debfile = os.path.join(path, fname)
                #if os.path.basename(debfile) in data:
                    # print >> sys.stderr, "Skipping", debfile
                #    pass
                # else:
                if parallel:
                    output[debfile] = p.apply_async(analyze, (debfile,))
                else:
                    out = analyze(debfile)
                    if out:
                        print(out)

            if parallel:
                for debfile, result in output.items():
                    sys.stderr.write("Analyzing %s ...\n" % debfile)
                    print(result.get())

if __name__ == "__main__":
    main()
    # profile_main()
