#include<gmp.h>
#include <zmq.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include"zhelpers.h"
#include"cipher.h"


paillier_ciphertext_t** perform_sip(void* socket, paillier_pubkey_t* pubkey, paillier_prvkey_t* prikey, paillier_plaintext_t** plaintexts, int len, int* nlen)
{
	char* prikeyhex = paillier_prvkey_to_hex(prikey);
	char* pubkeyhex = paillier_pubkey_to_hex(pubkey);
	paillier_ciphertext_t** c = (paillier_ciphertext_t**)malloc(len*sizeof(paillier_ciphertext_t*));
	int i;
	for(i=0;i<len;i++){
		c[i] = paillier_enc(NULL,pubkey,plaintexts[i],&paillier_get_rand_devrandom);
	}
	s_send(socket,pubkeyhex);
	free(pubkeyhex);
	s_recv(socket); // ignore response
	s_send(socket,prikeyhex);
	free(prikeyhex);
	s_recv(socket); // ignore response
	s_sendcipherarray(socket,c,len);
	free_cipherarray(c,len);
	// read a cipher array as the result
	paillier_ciphertext_t** z = s_readcipherarray(socket,nlen);

	return z;
}

int main (void)
{
	paillier_pubkey_t* pkey;
	paillier_prvkey_t* skey;
	paillier_keygen(32,&pkey,&skey,&paillier_get_rand_devrandom);


	void *context = zmq_ctx_new ();

	// Socket to talk to server
	printf ("Connecting to hello world server.\n");
	gmp_printf("n: %Zd, lambda: %Zd\n",pkey->n,skey->lambda);
	void *requester = zmq_socket (context, ZMQ_REQ);
	zmq_connect (requester, "ipc:///tmp/karma");
	int len = 4;
	paillier_plaintext_t** c = (paillier_plaintext_t**)malloc(len*sizeof(paillier_plaintext_t*));
	int i,j;
	for(i=0;i<len;i++){
		c[i] = paillier_plaintext_from_ui(i+1);
	}

	int request_nbr;
	for (request_nbr = 0; request_nbr != 10; request_nbr++) {
		int nlen;

		paillier_ciphertext_t** z = perform_sip(requester,pkey,skey,c,len,&nlen);
		paillier_plaintext_t* p = paillier_plaintext_from_ui(0);
		for(j=0;j<nlen;j++){
			paillier_dec(p,pkey,skey,z[j]);
			gmp_printf("Recieved %Zd as inner product, unblinded\n",p->m);
		}

		free_cipherarray(z,nlen);
		z = perform_sip(requester,pkey,skey,c,len,&nlen);
		for(j=0;j<nlen;j++){
			paillier_dec(p,pkey,skey,z[j]);
			gmp_printf("Recieved %Zd as inner product, unblinded\n",p->m);
		}
		paillier_freeplaintext(p);

		free_cipherarray(z,nlen);

	}
	sleep (2);
	zmq_close (requester);
	zmq_ctx_destroy (context);
	return 0;
}

