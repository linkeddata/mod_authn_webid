all:
	apxs -c -I/usr/include/rasqal -lcrypto -lrdf mod_authn_webid.c

install:
	apxs -c -i -I/usr/include/rasqal -lcrypto -lrdf mod_authn_webid.c

clean:
	rm -f mod_authn_webid.{la,lo,slo,o} -r .libs
