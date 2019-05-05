for lang in pt ja it fi fr es de zh rp pl_PL hi_IN tr_TR
do
	msgmerge -N -U $lang/tqslapp.po ../tqslapp.pot
done
