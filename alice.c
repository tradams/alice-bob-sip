#include<gmp.h>
#include <zmq.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include"zhelpers.h"
#include"cipher.h"

const int SIZE=4;

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
	char* ign = s_recv(socket); // ignore response
	free(ign);
	s_send(socket,prikeyhex);
	free(prikeyhex);
	ign = s_recv(socket); // ignore response
	free(ign);
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
	paillier_plaintext_t** ai = (paillier_plaintext_t**)malloc(nlen*sizeof(paillier_plaintext_t*));
	
	printf("%i items returned\n",nlen);
	//TODO: find out why I can't use free_cipherarray here?
	for(j=0;j<nlen;j++){
		ai[j] = paillier_dec(NULL,pkey,skey,z[j]);
		gmp_printf("Recieved %Zd as inner product, unblinded\n",ai[j]->m);
		paillier_freeciphertext(z[j]);
	}
	//free(z);


	z = perform_sip(socket,pkey,skey,texts,len,&nlen);
	paillier_plaintext_t** qi = (paillier_plaintext_t**)malloc(nlen*sizeof(paillier_plaintext_t*));
	for(j=0;j<nlen;j++){
		qi[j] = paillier_dec(NULL,pkey,skey,z[j]);
		mpz_sub(qi[j]->m,qi[j]->m,pkey->n);
		gmp_printf("Recieved %Zd as inner product, unblinded\n",qi[j]->m);
	}
	free_cipherarray(z,nlen);
	
	mpz_t* aix = (mpz_t*)malloc(len*sizeof(mpz_t));
	mpz_t tmp;
	for(i=0;i<nlen;i++){
		mpz_init(aix[i]);
		mpz_sub(aix[i],aix[i],qi[i]->m);
	}
	mpz_init(tmp);
	for(i=0;i<SIZE;i++){
		for(j=0;j<nlen;j++){
			mpz_mul(tmp,ai[j*SIZE+i]->m,texts[i]->m);
			mpz_add(aix[j],aix[j],tmp);
		}
	}
	
	for(i=0;i<nlen;i++){
		gmp_printf("ANSWER: %Zd\n",aix[i]);
		mpz_clear(aix[i]);
		paillier_freeplaintext(ai[i]);
		paillier_freeplaintext(qi[i]);
	}
	free(aix);
	mpz_clear(tmp);
	//TODO: ask keith why this doesn't work
	//free(ai);
	


}

int main (void)
{
	paillier_pubkey_t* pkey;
	paillier_prvkey_t* skey;
	paillier_keygen(256,&pkey,&skey,&paillier_get_rand_devrandom);


	void *context = zmq_ctx_new ();

	// Socket to talk to server
	printf ("Connecting to hello world server.\n");
	gmp_printf("n: %Zd, lambda: %Zd\n",pkey->n,skey->lambda);
	void *requester = zmq_socket (context, ZMQ_REQ);
	zmq_connect (requester, "ipc:///tmp/karma");
	paillier_plaintext_t** c = (paillier_plaintext_t**)malloc(SIZE*sizeof(paillier_plaintext_t*));
	int i,j;
	for(i=0;i<SIZE;i++){
		c[i] = paillier_plaintext_from_ui(i+1);
	}

	int request_nbr;
	for (request_nbr = 0; request_nbr != 10; request_nbr++) {
		perform_xSigmax(requester,pkey,skey,c,SIZE);

	}
	sleep (2);
	zmq_close (requester);
	zmq_ctx_destroy (context);
	return 0;
}

