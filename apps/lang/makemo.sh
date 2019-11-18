for lang in de es fi fr hi_IN it ja pl_PL pt ru tr_TR zh
do
	msgfmt $lang/tqslapp.po -o $lang/tqslapp.mo
done
