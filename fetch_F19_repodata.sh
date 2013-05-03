rsync --progress -avrz --delete --exclude "*.sqlite.bz2" --exclude "*-presto*" --exclude "*-fileli*" rsync://dl.fedoraproject.org/fedora-enchilada/linux/development/19/x86_64/os/repodata data/
