#!/bin/sh

cd ../rpmgrill/

perl -C63 -I$(pwd)/lib ./bin/nvr2rpmgrill $1
perl -C63 -I$(pwd)/lib ./bin/rpmgrill $1
