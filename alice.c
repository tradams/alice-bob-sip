#include<gmp.h>
#include <zmq.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include"zhelpers.h"
#include"cipher.h"


int main (void)
{
	paillier_pubkey_t* pkey;
	paillier_prvkey_t* skey;
	paillier_keygen(16,&pkey,&skey,&paillier_get_rand_devrandom);
	char* pubkeyhex = paillier_pubkey_to_hex(pkey);

	void *context = zmq_ctx_new ();

	// Socket to talk to server
	printf ("Connecting to hello world server.\n");
	void *requester = zmq_socket (context, ZMQ_REQ);
	zmq_connect (requester, "ipc:///tmp/karma");

	int request_nbr;
	for (request_nbr = 0; request_nbr != 10; request_nbr++) {
		s_send(requester,pubkeyhex);
		printf ("Sending %s %d.\n",pubkeyhex, request_nbr);

		paillier_ciphertext_t* c = s_readcipher(requester);
		paillier_plaintext_t* a = paillier_dec(NULL,pkey,skey,c);
		gmp_printf("Recieved %Zd \n",a->m);
		paillier_freeciphertext(c);
		paillier_freeplaintext(a);
	//	char* answer = s_recv(requester);
		//zmq_msg_t reply;
		//zmq_msg_init (&reply);
		//zmq_msg_recv (&reply, requester, 0);

	//	printf ("Received %s %d\n",answer, request_nbr);
	//	free(answer);
		//zmq_msg_close (&reply);
	}
	sleep (2);
	zmq_close (requester);
	zmq_ctx_destroy (context);
	return 0;
}

