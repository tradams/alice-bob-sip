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

paillier_plaintext_t* perform_xSigmax(void* socket, paillier_pubkey_t* pkey, paillier_prvkey_t* skey, paillier_plaintext_t** texts, int len)
{
	int i,j;
	int nlen;

	paillier_ciphertext_t** z = perform_sip(socket,pkey,skey,texts,len,&nlen);
	paillier_plaintext_t** ai = (paillier_plaintext_t**)malloc(len*sizeof(paillier_plaintext_t*));
	printf("%i items returned\n",nlen);
	for(j=0;j<nlen;j++){
		ai[j] = paillier_dec(NULL,pkey,skey,z[j]);
		gmp_printf("Recieved %Zd as inner product, unblinded\n",ai[j]->m);
	}

	free_cipherarray(z,nlen);

	z = perform_sip(socket,pkey,skey,texts,len,&nlen);
	paillier_plaintext_t* qi = NULL;
	for(j=0;j<nlen;j++){
		qi = paillier_dec(NULL,pkey,skey,z[j]);
		mpz_sub(qi->m,qi->m,pkey->n);
		gmp_printf("Recieved %Zd as inner product, unblinded\n",qi->m);
	}
	free_cipherarray(z,nlen);
	
	mpz_t aix;
	mpz_t tmp;
	mpz_init(aix);
	mpz_init(tmp);
	for(i=0;i<len;i++){
		mpz_mul(tmp,ai[i]->m,texts[i]->m);
		mpz_add(aix,aix,tmp);
	}
	
	mpz_sub(aix,aix,qi->m);
	gmp_printf("ANSWER: %Zd\n",aix);
	mpz_clear(aix);
	
	
	for(i=0;i<nlen;i++){
		paillier_freeplaintext(ai[i]);
	}
	free(ai);
	paillier_freeplaintext(qi);


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
		perform_xSigmax(requester,pkey,skey,c,len);

	}
	sleep (2);
	zmq_close (requester);
	zmq_ctx_destroy (context);
	return 0;
}

