#!/usr/bin/env python

import os
import sys
import json
from yum.mdparser import MDParser
from yum import repoMDObject
import cmd
import subprocess

blurb = """
$ pip install requests
"""

try:
    import requests
except ImportError as exc:
    print(exc)
    print("Dependencies not met, use following steps!")
    print(blurb)
    sys.exit(-1)


BASE_URL = "http://dl.fedoraproject.org/pub/fedora/linux/development/19/x86_64/os/"
database = {}
sections = {}

bug_template = """
Description of problem:

http://fedoraproject.org/wiki/Packaging:Guidelines#PIE says that "you MUST
enable the PIE compiler flags if your package is long running ...".

However, currently %s is not being built with PIE flags. This is a
clear violation of the packaging guidelines.

This issue (in its wider scope) is being discussed at,

https://fedorahosted.org/fesco/ticket/1104

https://lists.fedoraproject.org/pipermail/devel/2013-March/180827.html

Version-Release number of selected component (if applicable):

%s

How reproducible:

You can use following programs to check if a package is hardened:

http://people.redhat.com/sgrubb/files/rpm-chksec

OR

https://github.com/kholia/checksec

Steps to Reproduce:

Get scanner.py from https://github.com/kholia/checksec

$ ./scanner.py %s
%s"""

bug_template_setxid = """
Description of problem:

http://fedoraproject.org/wiki/Packaging:Guidelines#PIE says that "you MUST
enable the PIE compiler flags if your package has suid binaries...".

However, currently %s is not being built with PIE flags. This is a
clear violation of the packaging guidelines.

This issue (in its wider scope) is being discussed at,

https://fedorahosted.org/fesco/ticket/1104

https://lists.fedoraproject.org/pipermail/devel/2013-March/180827.html

Version-Release number of selected component (if applicable):

%s

How reproducible:

You can use following programs to check if a package is hardened:

http://people.redhat.com/sgrubb/files/rpm-chksec

OR

https://github.com/kholia/checksec

Steps to Reproduce:

Get scanner.py from https://github.com/kholia/checksec

$ ./scanner.py %s
%s"""


from scanner import analyze

pkg = None

def fetch(url, destination):
    r = requests.get(url)
    with open(destination, "wb") as f:
        f.write(r.content)


def load():
    repomdpath = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             "data", "repodata", "repomd.xml")
    rmdo = repoMDObject.RepoMD("F19", repomdpath)
    plocation = rmdo.repoData["primary"].location[1]
    plocation = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             "data", plocation)
    parser = MDParser(plocation)
    for pkg in parser:
        database[pkg["name"]] = dict(pkg)

    print 'read: %s packages (%s suggested)' % (parser.count, parser.total)


class Fedora(cmd.Cmd):
    def do_search(self, package):
        for key in database.keys():
            if package in key:
                print(key)

    def do_analyze(self, package):
        try:
            filename = os.path.basename(database[package]["location_href"])
        except:
            print("package not found!")
            return

        destination = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                   "data", ".cache", filename)
        url = BASE_URL + database[package]["location_href"]
        if not os.path.exists(destination):
            print(url, "=>", destination)
            fetch(url, destination)
        data = json.loads(analyze(destination, show_errors=False))
        print json.dumps(data, sort_keys=True, indent=4,
                         separators=(',', ': '))

    def do_describe(self, package):
        print "description:", database[package]["description"]
        print "group:", database[package]["group"]
        print "ver + rel:", database[package]["ver"], database[package]["rel"]

    def do_dump(self, line):
        print(database.keys())

    def do_report(self, package):
        try:
            filename = os.path.basename(database[package]["location_href"])
        except:
            print("package not found!")
            return

        destination = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                   "data", ".cache", filename)
        url = BASE_URL + database[package]["location_href"]
        if not os.path.exists(destination):
            print(url, "=>", destination)
            fetch(url, destination)
        data = analyze(destination, show_errors=False, opformat="csv")
        lines = data.split('\n')
        build = lines[0].split(',')[1]

        if pkg and package.startswith(pkg):
            package = pkg
            print "\n!!!! Setting package to %s !!!!\n\n\n" % pkg
        elif pkg:
            print "%s is too different from %s" % (pkg, package)
            return

        bug_summary = "%s package should be built with PIE flags" % package
        bug_data = bug_template % (package, build, build, data)
        # cmd = "bugzilla --bugzilla=https://partner-bugzilla.redhat.com/xmlrpc.cgi new --product Fedora " \
        cmd = "bugzilla new --product Fedora " \
                "--component '%s' --version '19' --summary '%s' --comment '%s'" % \
                (package, bug_summary, bug_data)
        print cmd
        p = subprocess.Popen(cmd, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        o, e = p.communicate()
        print o,e


    def do_setpkg(self, line):
        global pkg
        pkg = line.rstrip()

    def do_unsetpkg(self, line):
        global pkg
        pkg = None

    def do_about(self, line):
        print("rpm-shell v0.01 ;)")

    def do_sections(self, line=None):
        for key in database.keys():
            v = database[key]
            l = sections.get(v["group"], [])
            l.append(key)
            sections[v["group"]] = l
        print(sections.keys())

    def do_section(self, line):
        self.do_sections()
        for key in sections.keys():
            if line in key:
                print("List for", key, ":", sections[key])

    def preloop(self):
        print("Loading database ...")
        load()

    def do_EOF(self, line):
        return True


if __name__ == "__main__":
    Fedora().cmdloop()
