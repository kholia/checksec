#!/usr/bin/env python

import rpm
import os

ts = rpm.TransactionSet()

known_files = {}

print("[+] Loading database...")

ts.setVSFlags((rpm._RPMVSF_NOSIGNATURES|rpm._RPMVSF_NODIGESTS))
for hdr in ts.dbMatch():
    fi = hdr.fiFromHeader()
    for f in fi:
        known_files[f] = True
    # print '%s-%s:%s-%s.%s' % (hdr['name'],
    #    hdr['epochnum'],hdr['version'],hdr['release'],
    #    hdr['arch'])

paths = known_files.keys()

print("[+] Scanning system...\n")
for (path, _, files) in os.walk("/"):
    for fname in files:
        path = os.path.join(path, fname)
        if os.path.exists(path) and path not in paths:
            # is it excluded?
            if not path.startswith("/home"):
                print(path)
