http_inject:
	gcc -o http_inject http_inject.c -lnet -lpcap
clean:
	rm -f http_inject
