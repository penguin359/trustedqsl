for lang in de es fi fr hi_IN it ja pl_PL pt ru tr_TR zh
do
	msgmerge -N -U $lang/tqslapp.po ../tqslapp.pot
done
