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
    from debian import deb822
    import requests
except ImportError as exc:
    print(exc)
    print("Dependencies not met, use following steps!")
    print(blurb)
    sys.exit(-1)

from io import BytesIO
import subprocess
import os
import stat
import bz2
import gzip
import cmd
import json

if len(sys.argv) > 1:
    BASE_URL = "http://mirrors.kernel.org/debian/"
else:
    BASE_URL = "http://archive.ubuntu.com/ubuntu/"
database = {}
sections = {}
opformat = "json"

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
        if returncode == 0 and opformat == "json":
            try:
                for kvp in out.rstrip().split(","):
                    key, value = kvp.split("=")
                    fileinfo[key] = value
            except Exception:
                pass

    print(json.dumps(output, sort_keys=True, indent=4,
                         separators=(',', ': ')))

def fetch(url, destination):
    r = requests.get(url)
    with open(destination, "wb") as f:
        f.write(r.content)


def load(fname):
    if fname.endswith('.gz'):
        f = gzip.GzipFile(fname, 'r')
    elif fname.endswith('.bz2'):
        f =  bz2.BZ2File(fname, "r")
    else:
        raise RuntimeError("file '%s' has unexpected extension" % fname)

    for stanza in deb822.Sources.iter_paragraphs(f):
        database[stanza['package']] = dict(stanza)


class Ubuntu(cmd.Cmd):
    def do_search(self, package):
        for key in database.keys():
            if package in key:
                print(key)

    def do_analyze(self, package):
        try:
            filename = os.path.basename(database[package]["Filename"])
        except Exception:
            # print("package not found!", file=sys.stderr)
            return

        destination = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data", ".cache", filename)
        url = BASE_URL + database[package]["Filename"]
        if not os.path.exists(destination):
            print(url, "=>", destination)
            fetch(url, destination)
        analyze(destination, package, database[package]["Section"])

    def do_describe(self, package):
        print("Description:", database[package]["Description"])
        print("Section:", database[package]["Section"])
        print("Version:", database[package]["Version"])

    def do_dump(self, line):
        print(database.keys())

    def do_about(self, line):
        print("deb-shell v0.01 ;)")

    def do_sections(self, line=None):
        for key in database.keys():
            v = database[key]
            l = sections.get(v["Section"], [])
            l.append(key)
            sections[v["Section"]] = l
        print(sections.keys())

    def do_section(self, line):
        self.do_sections()
        for key in sections.keys():
            if line in key:
                print("List for", key, ":", sections[key])


    def preloop(self):
        if len(sys.argv) < 2:
            lookup_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                    "data")
        else:
            lookup_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                    "data", sys.argv[1])
        for (path, _, files) in os.walk(lookup_path):
            for fname in files:
                fpath = os.path.join(path, fname)
                if "Packages.gz" in fpath:
                    print("Loading", fpath)
                    load(fpath)

    def do_EOF(self, line):
        return True

if __name__ == "__main__":
    Ubuntu().cmdloop()
