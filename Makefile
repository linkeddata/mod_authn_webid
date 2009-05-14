all:
	apxs -c -I/usr/include/rasqal -lcrypto -lrdf mod_auth_foafssl.c

install:
	apxs -c -i -I/usr/include/rasqal -lcrypto -lrdf mod_auth_foafssl.c

clean:
	rm -f mod_auth_foafssl.{la,lo,slo,o} -r .libs
