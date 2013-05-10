#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pyclamd

cd = pyclamd.ClamdNetworkSocket()
try:
    cd.ping()
except pyclamd.ConnectionError:
    raise ValueError, "could not connect to clamd server either by unix or network socket"

# print version
# print "Version : \n{0}\n".format(cd.version())

# force a db reload
# cd.reload()

# print stats
# print "\n{0}\n".format(cd.stats())

# write test file with EICAR test string
open('/tmp/EICAR','w').write(cd.EICAR())

# write test file without virus pattern
open('/tmp/NO_EICAR','w').write('no virus in this file')

# scan files
print "\n{0}\n".format(cd.scan_file('/tmp/EICAR'))
print "\n{0}\n".format(cd.scan_file('/tmp/NO_EICAR'))

# scan a stream
print "\n{0}\n".format(cd.scan_stream(cd.EICAR()))

