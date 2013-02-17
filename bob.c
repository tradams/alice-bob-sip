#include<gmp.h>
#include<stdio.h>
#include<pthread.h>
#include<stdlib.h>
#include<zmq.h>
#include"zhelpers.h"
#include <unistd.h>
#include <string.h>
#include"cipher.h"



// length of return known by number of columns
paillier_plaintext_t** perform_sip_b(void* socket, paillier_plaintext_t*** sigma, int cols)
{
	// alice will send me the key first
	char* pubkeyhex = s_recv(socket);
	paillier_pubkey_t* pkey = paillier_pubkey_from_hex(pubkeyhex);
	free(pubkeyhex);
	//send dummy response
	s_send(socket,"roger");
	char* prikeyhex = s_recv(socket);
	paillier_prvkey_t* skey = paillier_prvkey_from_hex(prikeyhex,pkey);
	free(prikeyhex);
	gmp_printf("n: %Zd, lambda: %Zd\n",pkey->n,skey->lambda);
	//send dummy response
	s_send(socket,"roger");

	int len;
	//read the c's
	paillier_ciphertext_t** c = s_readcipherarray(socket,&len);
	paillier_plaintext_t** bs = (paillier_plaintext_t**)malloc(cols*sizeof(paillier_plaintext_t*));
	paillier_ciphertext_t** zs = (paillier_ciphertext_t**)malloc(cols*sizeof(paillier_ciphertext_t*));
	paillier_ciphertext_t* z = paillier_create_enc_zero();
	paillier_ciphertext_t* res = paillier_create_enc_zero();
	paillier_ciphertext_t* t0 = paillier_create_enc_zero();
	paillier_plaintext_t* test = paillier_plaintext_from_ui(0);
	
	int i,j;
	for(i=0;i<cols;i++){
		for(j=0;j<len;j++){
			paillier_dec(test,pkey,skey,c[j]);
			gmp_printf("%Zd^%Zd\n",test->m,sigma[i][j]->m);
			paillier_exp(pkey,res,c[j],sigma[i][j]);
			if(j==0)
				mpz_set(z->c,res->c);
			else{ 
				paillier_mul(pkey,t0,z,res);
				mpz_set(z->c,t0->c);
			}
		}
		// create the b and blind this result
		bs[i] = paillier_plaintext_from_si(-1);
		paillier_enc(res,pkey,bs[i],&paillier_get_rand_devrandom);
		zs[i] = paillier_create_enc_zero();
		paillier_mul(pkey,zs[i],z,res);
	}
	paillier_freeciphertext(res);
	paillier_freeciphertext(z);
	paillier_freeciphertext(t0);
	free_cipherarray(c,len);


	s_sendcipherarray(socket,zs,cols);
	free_cipherarray(zs,cols);
	
	return bs;

}

int main(){
	paillier_pubkey_t* pkey;

	void* ctx = zmq_ctx_new();

	void *responder = zmq_socket (ctx, ZMQ_REP);
	zmq_bind (responder, "ipc:///tmp/karma");
	int i,j;
	int len = 4;
	int rows = 4;
	paillier_plaintext_t*** sigma = (paillier_plaintext_t***)malloc(len*sizeof(paillier_plaintext_t**));
	for(i=0;i<len;i++){
		sigma[i] = (paillier_plaintext_t**)malloc(rows*sizeof(paillier_plaintext_t**));
		for(j=0;j<rows;j++){
			sigma[i][j] = paillier_plaintext_from_ui(j+1);
		}

	}

	while (1) {
		

		paillier_plaintext_t** bs = perform_sip_b(responder,sigma,len);
		perform_sip_b(responder,&bs,1);	
		//now the fun free process


	}
	// We never get here but if we did, this would be how we end
	zmq_close (responder);
	zmq_ctx_destroy (ctx);


	return 0;
}
