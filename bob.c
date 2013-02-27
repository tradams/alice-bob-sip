#include<gmp.h>
#include<stdio.h>
#include<pthread.h>
#include<stdlib.h>
#include<zmq.h>
#include"zhelpers.h"
#include<unistd.h>
#include<string.h>
#include"cipher.h"
#include<math.h>
#include<csv.h>
#include<getopt.h>


struct sig_data {
	paillier_plaintext_t*** array;
	int row,col;
	int maxrow,maxcol;
    int scale_factor;
};

typedef paillier_plaintext_t*** Sigma;
typedef paillier_plaintext_t** Vec;

// length of return known by number of columns
Sigma perform_sip_b(void* socket, paillier_pubkey_t* pkey,  Sigma* sigma, int cols,int lsigma, gmp_randstate_t rand)
{
	int len;
	//read the c's
	paillier_ciphertext_t** c = s_readcipherarray(socket,&len);
	Sigma bs = (Sigma)malloc(lsigma*sizeof(Vec));
	paillier_ciphertext_t** zs = (paillier_ciphertext_t**)malloc(lsigma*cols*sizeof(paillier_ciphertext_t*));
	paillier_ciphertext_t* z = paillier_create_enc_zero();
	paillier_ciphertext_t* res = paillier_create_enc_zero();
	
    int t0 = time(NULL);
    //printf("Starting actual calculation of inner product\n");
	int i,j,k;
	for(k=0;k<lsigma;k++){
		bs[k] = (Vec)malloc(cols*sizeof(paillier_plaintext_t*));
		for(i=0;i<cols;i++){
			for(j=0;j<len;j++){
				paillier_exp(pkey,res,c[j],sigma[k][i][j]);
				if(j==0)
					mpz_set(z->c,res->c);
				else{ 
					paillier_mul(pkey,z,z,res);
				}
			}
			// create the b and blind this result
            int val = -1;
			bs[k][i] = paillier_plaintext_from_si(val);
			paillier_enc_r(res,pkey,bs[k][i],rand);
            mpz_set_si(bs[k][i]->m,-val);
			zs[cols*k+i] = paillier_create_enc_zero();
			paillier_mul(pkey,zs[cols*k+i],z,res);
		}
	}
    int t1 = time(NULL);
    //printf("Calculation ended\n");
    printf ("time = %d secs\n", t1 - t0);
	paillier_freeciphertext(res);
	paillier_freeciphertext(z);
	free_cipherarray(c,len);


	s_sendcipherarray(socket,zs,lsigma*cols);
	free_cipherarray(zs,lsigma*cols);

	
	return bs;

}

void field_parsed(void* s, size_t len, void* data)
{
	struct sig_data* sig = (struct sig_data*)data;
	char* c = (char*)malloc(len+1);
	memcpy(c,s,len);	
	c[len] = 0;
	sig->array[sig->col][sig->row] = paillier_plaintext_from_si((int)(atof(c)*sig->scale_factor));
	free(c);

	sig->col = sig->col+1;

}

void row_parsed(int c, void* data)
{
	struct sig_data* sig = (struct sig_data*)data;
	sig->row = sig->row+1;
	sig->col = 0;

}



Sigma read_sigma(const char* file,int row,int col, int scale_factor)
{
	printf("reading file %s for sigma\n",file);
	int i;
	struct sig_data data;
	data.maxcol = col;
	data.maxrow = row;
    data.scale_factor = scale_factor;
	data.array = (Sigma)malloc(data.maxrow*sizeof(Vec));
	for(i=0;i<data.maxrow;i++)	
		data.array[i] = (Vec)malloc(data.maxcol*sizeof(paillier_plaintext_t*));
	data.row = 0;
	data.col = 0;

	FILE* fp;
	struct csv_parser p;
	char buf[1024];
	size_t bytes_read;
	if(csv_init(&p,0)) {
		fprintf(stderr, "Failed to initialize parser\n");
		exit(EXIT_FAILURE);
	}
	
	fp = fopen(file,"rb");
	if(!fp){
		fprintf(stderr,"Failed to open sigma file %s\n",strerror(errno));
		exit(EXIT_FAILURE);
	}

	while ((bytes_read=fread(buf,1,1024,fp)) > 0){
		if(!csv_parse(&p,buf,bytes_read,field_parsed,row_parsed,&data)){
			fprintf(stderr, "Failed to parse file: %s\n",csv_strerror(csv_error(&p)));
		}
	}
	csv_fini(&p,field_parsed,row_parsed,&data);
	csv_free(&p);
	return data.array;

}
void free_sigma(Sigma s,int rows, int cols)
{
	int i,j;
	for(i=0;i<rows;i++){
		for(j=0;j<cols;j++){
			paillier_freeplaintext(s[i][j]);
		}
		free(s[i]);
	}
	free(s);
}

struct opts {
    int size;
    int scale;
    char* pkeyhex;
    int pkeyset;
};

void parse_options(int argc, char** argv, struct opts* opts)
{
    int c;
     
    opts->pkeyset = 0;
    while (1)
    {
        static struct option long_options[] =
        {
            {"dim",    required_argument, 0, 'd'},
            {"scale",  required_argument, 0, 's'},
            {"pkey",  required_argument, 0, 'p'},
            {0, 0, 0, 0}
        };
        int option_index = 0;

        c = getopt_long (argc, argv, "d:s:p:",
                       long_options, &option_index);

        if (c == -1)
            break;

        switch (c)
        {
            case 'd':
              opts->size = atoi(optarg);
              break;
            case 's':
              opts->scale = atoi(optarg);
              break;
            case 'p':
              opts->pkeyhex = optarg;
              opts->pkeyset = 1;
              break;

            case '?':
              /* getopt_long already printed an error message. */
              break;
        }
    }
}

int main(int argc, char** argv){
	int i,j;
	int files = 9;	
	char** sigmaFiles = (char**)malloc(files*sizeof(char*));
	sigmaFiles[0] = "sigmas/Alternative.csv";
	sigmaFiles[1] = "sigmas/Blues.csv";
	sigmaFiles[2] = "sigmas/Electorinic.csv";
	sigmaFiles[3] = "sigmas/Folk.csv";
	sigmaFiles[4] = "sigmas/Funk.csv";
	sigmaFiles[5] = "sigmas/Jazz.csv";
	sigmaFiles[6] = "sigmas/Pop.csv";
	sigmaFiles[7] = "sigmas/Rap.csv";
	sigmaFiles[8] = "sigmas/Rock.csv";

	void* ctx = zmq_ctx_new();

	void *responder = zmq_socket (ctx, ZMQ_REP);
	zmq_bind (responder, "ipc:///tmp/karma");
    struct opts options;
    parse_options(argc,argv, &options);

    if(options.size <= 0 || options.scale <= 0){
        fprintf(stderr,"Size and scale must be greater than 0\n");
        exit(EXIT_FAILURE);
    }

	Sigma* sigmas = (Sigma*)malloc(files*sizeof(Sigma));
	for(i=0;i<files;i++){
		sigmas[i] = read_sigma(sigmaFiles[i],options.size,options.size,options.scale);
	}

	char* pubkeyhex = s_recv(responder);
    printf("%s pubkeyhex\n",pubkeyhex);
	paillier_pubkey_t* pkey = paillier_pubkey_from_hex(pubkeyhex);
    gmp_printf("n = %Zd\n",pkey->n);
	free(pubkeyhex);
    s_send(responder,"Roger");

    gmp_randstate_t rand;
    init_rand(rand,&paillier_get_rand_devurandom,pkey->bits / 8 + 1);
	while (1) {
		//printf("Waiting for other end to initiate SIP\n");
		Sigma bs = perform_sip_b(responder,pkey,sigmas,options.size,files,rand);
		//printf("Sent response back, waiting again\n");
		Sigma bss = perform_sip_b(responder,pkey,&bs,files,1,rand);	
	//	printf("Final answer sent\n");
		free_sigma(bss,1,files);
		free_sigma(bs,files,options.size);
	}
	// We never get here but if we did, this would be how we end
	zmq_close (responder);
	zmq_ctx_destroy (ctx);


	return 0;
}
