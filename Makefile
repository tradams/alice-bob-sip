BASE=/home/tra26/karma/local
LIB=$(BASE)/lib
INC=$(BASE)/include
DBG=
build:
	gcc -lgmp -L$(LIB) -I$(INC) -o bob.out bob.c -lpaillier  -lzmq -lcsv $(DBG)
	gcc -lgmp -L$(LIB) -I$(INC) -o alice.out alice.c -lpaillier  -lzmq -lcsv $(DBG)
