#include<gmp.h>
#include<stdio.h>
#include<pthread.h>
#include<stdlib.h>
#include<zmq.h>
#include"zhelpers.h"
#include <unistd.h>
#include <string.h>
#include"cipher.h"



int main(){
	int i =0;
	paillier_pubkey_t* pkey;

	void* ctx = zmq_ctx_new();

	void *responder = zmq_socket (ctx, ZMQ_REP);
	zmq_bind (responder, "ipc:///tmp/karma");

	while (1) {
		// Wait for next request from client
		char* hexkey =  s_recv(responder);
		printf ("Received %s\n",hexkey);

		pkey = paillier_pubkey_from_hex(hexkey);
		free(hexkey);

		paillier_plaintext_t* a = paillier_plaintext_from_ui(5);
		paillier_ciphertext_t* c = paillier_enc(NULL,pkey,a,&paillier_get_rand_devurandom);

		// we now have the encrypted value from the other side
		s_sendcipher(responder,c);

		// Do some 'work'
		sleep (1);

	}
	// We never get here but if we did, this would be how we end
	zmq_close (responder);
	zmq_ctx_destroy (ctx);


	return 0;
}
