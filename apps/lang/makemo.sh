for lang in pt ja it fi fr es de zh rp pl_PL hi_IN tr_TR
do
	msgfmt $lang/tqslapp.po -o $lang/tqslapp.mo
done
