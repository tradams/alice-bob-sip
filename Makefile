build:
	gcc -lgmp -L/home/tra26/karma/local/lib -I/home/tra26/karma/local/include -o bob.out bob.c -lpaillier  -lzmq -lcsv -g
	gcc -lgmp -L/home/tra26/karma/local/lib -I/home/tra26/karma/local/include -o alice.out alice.c -lpaillier  -lzmq -lcsv -g 
