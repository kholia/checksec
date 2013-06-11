set terminal png size 800,600
# set terminal png nocrop enhanced font arial 8 size 800,600
# set terminal png transparent nocrop enhanced font arial 8 size 420,320
set output 'PIE-usage-F19.png'
set boxwidth 0.9 absolute
set grid ytics lt 0 lw 1 lc rgb "#bbbbbb"
set grid xtics lt 0 lw 1 lc rgb "#bbbbbb"
set style fill solid 1.00 border -1
set style histogram clustered gap 1 title offset character 0, 0, 0
set datafile missing '-'
set offset graph 0.1, graph 0.1, graph 0.1, graph 0.0
# set autoscale
set style data histograms
set xtics border in scale 1,0.5 nomirror offset character 0, 0, 0
set xtics   ("Stack Canary" 0.00000, "NX Stack" 1.00000, "RELRO" 2.00000, "PIE" 3.00000)
set title "Fedora 19, package hardening report\n(only packages containing ELF objects are considered)"
set ylabel "number of packages"
set yrange [ 0.00000 : * ] noreverse nowriteback
plot 'my.dat' u 1 ti col linecolor rgb "#00FF00", \
	'' u 2 ti col linecolor rgb "#FF0000", \
	'' u 3 ti col linecolor rgb "#FFFF00"
