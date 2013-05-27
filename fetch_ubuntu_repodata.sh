for item in main multiverse restricted universe
do
rsync --progress -avrz --exclude='*.bz2' rsync://archive.ubuntu.com/ubuntu/dists/raring/$item/binary-amd64/ data/ubuntu/$item
done
