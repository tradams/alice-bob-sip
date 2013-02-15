#ifndef __CIPHER_H__
#define __CIPHER_H__

#include<gmp.h>
#include<paillier.h>
#include<zmq.h>



static paillier_ciphertext_t* x_readcipher_msg(zmq_msg_t* message, int size)
{
	void* cipher = malloc(size);  
	memcpy (cipher, zmq_msg_data (message), size);
	paillier_ciphertext_t* c = paillier_ciphertext_from_bytes(cipher,size);
	free(cipher);
	return c;
}

static paillier_ciphertext_t* s_readcipher(void* socket)
{
	zmq_msg_t message;
	zmq_msg_init (&message);
	int size = zmq_msg_recv (&message, socket, 0);
	if (size == -1)
		return NULL;

	paillier_ciphertext_t* c = x_readcipher_msg(&message,size);
	zmq_msg_close (&message);
	return c;
}


static void s_sendcipher_options(void* socket, paillier_ciphertext_t* cipher, int multipart)
{
	zmq_msg_t msg;
	int size;
	void* buf = paillier_ciphertext_to_bytelen(&size,cipher);
	int rc = zmq_msg_init_size(&msg,size);
	assert(rc==0);

	printf("%i size\n",size);
	memset(zmq_msg_data (&msg), 0, size);
	memcpy(zmq_msg_data (&msg), buf, size);
	int op = (multipart == 0)?ZMQ_SNDMORE:0;
	int sent = zmq_msg_send(&msg,socket,op);
	zmq_msg_close(&msg);
	assert(sent == size);
	free(buf);

}
static void s_sendcipher(void* socket, paillier_ciphertext_t* cipher)
{
	s_sendcipher_options(socket,cipher,0);
}


void s_sendcipherarray(void* socket, paillier_ciphertext_t** cipher, int len)
{

}

paillier_ciphertext_t** s_readcipherarray(void* socket, int* len)
{

	return 0;
}

#endif
