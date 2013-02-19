#ifndef __CIPHER_H__
#define __CIPHER_H__

#include<gmp.h>
#include<paillier.h>
#include<zmq.h>
#include<rpc/xdr.h>


struct msgblock {
	int flags;
	int len;
}; 
typedef struct msgblock mblock;

static mblock* x_getblock(zmq_msg_t* message,int size){
	mblock* block = (mblock*)malloc(sizeof(mblock));

	char *string = malloc (size + 1);
	memcpy (string, zmq_msg_data (message), size);
	string [size] = 0;
//	printf("\nGETBLOCK %s %i\n",string,size);
	int flag, len;
	sscanf(string,"%i %i",&flag,&len);
	block->flags = flag;
	block->len = len;
	free(string);
	return block;

}

static void x_getmsg(mblock* block,zmq_msg_t* message)
{

	char buf[50];
	int size=sprintf(buf,"%i %i", block->flags,block->len);

//	printf("Sending the following string: %s sizeof %i\n",buf,(int)strlen(buf));
	
	zmq_msg_init_size(message,size);

	memset(zmq_msg_data (message), 0, strlen(buf));
	memcpy(zmq_msg_data (message), buf, strlen(buf));

}


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
//	gmp_printf("Recv: %Zd %i\n",c->c,size);
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

	memset(zmq_msg_data (&msg), 0, size);
	memcpy(zmq_msg_data (&msg), buf, size);
	int op = (multipart == 0)?ZMQ_SNDMORE:0;
	int sent = zmq_msg_send(&msg,socket,op);
//	gmp_printf("Send: %Zd %i\n",cipher->c,size);
	zmq_msg_close(&msg);
	//assert(sent == size);
	free(buf);

}
static void s_sendcipher(void* socket, paillier_ciphertext_t* cipher)
{
	s_sendcipher_options(socket,cipher,1);
}


static void s_sendcipherarray(void* socket, paillier_ciphertext_t** cipher, int len)
{
	mblock b;
	b.len = len;
	b.flags=0;
	//printf("len in send: %i\n",len);
	zmq_msg_t msg;

	x_getmsg(&b,&msg);
	zmq_msg_send(&msg,socket,ZMQ_SNDMORE);
	zmq_msg_close(&msg);
	int i;
	for(i=0;i<len-1;i++){
		s_sendcipher_options(socket,cipher[i],0);
	}
	s_sendcipher(socket,cipher[len-1]);

}

static paillier_ciphertext_t** s_readcipherarray(void* socket, int* len)
{
	zmq_msg_t msg;
	zmq_msg_init (&msg);
	int rc = zmq_msg_recv (&msg, socket, 0);
	if (rc == -1){
		printf("crapping the bed %i\n",errno);
		return NULL;
	}

	mblock* block = x_getblock(&msg,rc);
	zmq_msg_close (&msg);
	//printf("len in read: %i\n",block->len);
	*len = block->len;
	paillier_ciphertext_t** array;
	array=(paillier_ciphertext_t**) malloc((block->len)*sizeof(paillier_ciphertext_t*));
	int i;

	int64_t more;
	size_t more_size = sizeof more;
	for(i=0;i<block->len;i++){
		zmq_msg_t part;
		rc = zmq_msg_init (&part);
		assert(rc==0);
		rc = zmq_msg_recv (&part, socket, 0);
		array[i] = x_readcipher_msg(&part,rc);
	//	gmp_printf("Recv: %Zd %i\n",array[i]->c,rc);
		assert(rc!=-1);
		rc = zmq_getsockopt (socket, ZMQ_RCVMORE, &more, &more_size);
		assert (rc == 0);
		zmq_msg_close (&part);
		if(!more && i!= block->len-1){
			return NULL;
		}
	}

	free(block);
	return array;
}

static void free_cipherarray(paillier_ciphertext_t** array, int len)
{
	int i;
	for(i=0;i<len;i++){
		paillier_freeciphertext(array[i]);
	}
	free(array);
}

#endif
