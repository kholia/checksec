#!/usr/bin/env python

from __future__ import print_function

import sys
from shove import Shove
import cStringIO
import re
import os
import stat
import multiprocessing
import threading
from collections import defaultdict

# global stuff
shove = Shove('sqlite:///dump.db')

print(type(shove))

print(shove)
