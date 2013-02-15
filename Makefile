build:
	gcc -lgmp -L/home/tra26/karma/local/lib -I/home/tra26/karma/local/include -o bob.out bob.c -lpaillier  -lzmq
	gcc -lgmp -L/home/tra26/karma/local/lib -I/home/tra26/karma/local/include -o alice.out alice.c -lpaillier  -lzmq
