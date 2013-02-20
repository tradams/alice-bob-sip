#include<gmp.h>
#include<zmq.h>
#include<string.h>
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include"zhelpers.h"
#include"cipher.h"
#include<csv.h>
#include<math.h>
#include<getopt.h>

struct classify_data {
    int col;
    int maxcol;
    int set;
    int scale_factor;
    void* socket;
    paillier_pubkey_t* pub;
    paillier_prvkey_t* prv;
    paillier_plaintext_t** texts;
};

paillier_ciphertext_t** perform_sip(void* socket, paillier_pubkey_t* pubkey, paillier_prvkey_t* prikey, paillier_plaintext_t** plaintexts, int len, int* nlen)
{
    char* prikeyhex = paillier_prvkey_to_hex(prikey);
    char* pubkeyhex = paillier_pubkey_to_hex(pubkey);
    paillier_ciphertext_t** c = (paillier_ciphertext_t**)malloc(len*sizeof(paillier_ciphertext_t*));
    int i;
    for(i=0;i<len;i++){
        c[i] = paillier_enc(NULL,pubkey,plaintexts[i],&paillier_get_rand_devurandom);
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

paillier_plaintext_t* perform_xSigmax(struct classify_data* data)
{
    printf("Going to start x'Sigmax calculation\n");
    void* socket = data->socket;
    paillier_pubkey_t* pkey = data->pub;
    paillier_prvkey_t* skey = data->prv;
    paillier_plaintext_t** texts = data->texts;
    int len = data->maxcol;
    int i,j;
    int nlen;

    paillier_ciphertext_t** z = perform_sip(socket,pkey,skey,texts,len,&nlen);
    paillier_plaintext_t** ai = (paillier_plaintext_t**)malloc(nlen*sizeof(paillier_plaintext_t*));
    
    //TODO: find out why I can't use free_cipherarray here?
    for(j=0;j<nlen;j++){
        ai[j] = paillier_dec(NULL,pkey,skey,z[j]);
        gmp_printf("Recieved %Zd as inner product, unblinded\n",ai[j]->m);
        paillier_freeciphertext(z[j]);
    }
    free(z);
    printf("Recieved the result of x'Sigma for all sigmas\n");

    z = perform_sip(socket,pkey,skey,texts,len,&nlen);
    paillier_plaintext_t** qi = (paillier_plaintext_t**)malloc(nlen*sizeof(paillier_plaintext_t*));
    for(j=0;j<nlen;j++){
        qi[j] = paillier_dec(NULL,pkey,skey,z[j]);
        //mpz_sub(qi[j]->m,qi[j]->m,pkey->n);
        gmp_printf("Recieved %Zd as inner product, unblinded\n",qi[j]->m);
    }
    free_cipherarray(z,nlen);

    printf("Recieved the result of bx\n");
    
    mpz_t* aix = (mpz_t*)malloc(len*sizeof(mpz_t));
    mpz_t tmp;
    for(i=0;i<nlen;i++){
        mpz_init(aix[i]);
        mpz_add(aix[i],aix[i],qi[i]->m);
    }
    mpz_init(tmp);
    for(i=0;i<data->maxcol;i++){
        for(j=0;j<nlen;j++){
            mpz_mul(tmp,ai[j*data->maxcol+i]->m,texts[i]->m);
            mpz_add(aix[j],aix[j],tmp);
        }
    }

    printf("Computed new answers\n");
    
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
void field_parsed(void* s, size_t len, void* pdata)
{
    struct classify_data* data = (struct classify_data*)pdata;
    char* c = (char*)malloc(len+1);
    memcpy(c,s,len);    
    c[len] = 0;
    if(data->col == 0) // this is the special column
        data->set = atoi(c);
    else
        data->texts[data->col-1] = paillier_plaintext_from_si((int)(atof(c)*data->scale_factor));
    free(c);

    data->col = data->col+1;
}

void row_parsed(int c, void* pdata)
{
    struct classify_data* data = (struct classify_data*)pdata;
    data->col = 0;
    //classify this data
    perform_xSigmax(data);
    int i;
    for(i=0;i<data->maxcol;i++){
        paillier_freeplaintext(data->texts[i]);
    }
}

struct opts {
    int size;
    char* file;
    int fileset;
    int scale;
    char* pkeyhex;
    int pkeyset;
    char* skeyhex;
    int skeyset;
};

void parse_options(int argc, char** argv, struct opts* opts)
{
    int c;
     
    opts->fileset = 0;
    opts->pkeyset = 0;
    opts->skeyset = 0;
    while (1)
    {
        static struct option long_options[] =
        {
            {"dim",    required_argument, 0, 'd'},
            {"file",   required_argument, 0, 'f'},
            {"scale",  required_argument, 0, 's'},
            {"pkey",  required_argument, 0, 'p'},
            {"skey",  required_argument, 0, 'P'},
            {0, 0, 0, 0}
        };
        int option_index = 0;

        c = getopt_long (argc, argv, "d:f:s:p:P:",
                       long_options, &option_index);

        if (c == -1)
            break;

        switch (c)
        {
            case 'd':
              opts->size = atoi(optarg);
              break;

            case 'f':
              opts->file = optarg;
              opts->fileset = 1;
              break;

            case 's':
              opts->scale = atoi(optarg);
              break;
            case 'p':
              opts->pkeyhex = optarg;
              opts->pkeyset = 1;
              break;
            case 'P':
              opts->skeyhex = optarg;
              opts->skeyset = 1;
              break;

            case '?':
              /* getopt_long already printed an error message. */
              break;
        }
    }
}

int main (int argc, char** argv)
{
    paillier_pubkey_t* pkey;
    paillier_prvkey_t* skey;
    paillier_keygen(128,&pkey,&skey,&paillier_get_rand_devrandom);


    void *context = zmq_ctx_new ();


    struct opts options;
    parse_options(argc,argv, &options);

    if(options.size <= 0 || options.scale <= 0 || !options.fileset){
        fprintf(stderr,"Size and scale must be greater than 0 and file must be set\n");
        exit(EXIT_FAILURE);
    }
    struct classify_data data;
    data.pub = pkey;
    data.prv = skey;
    data.maxcol = options.size;
    data.scale_factor = options.scale;
    data.texts = (paillier_plaintext_t**)malloc(options.size*sizeof(paillier_plaintext_t*));
    data.col = 0;

    // Socket to talk to server
    gmp_printf("n: %Zd, lambda: %Zd\n",pkey->n,skey->lambda);
    void *requester = zmq_socket (context, ZMQ_REQ);
    zmq_connect (requester, "ipc:///tmp/karma");

    data.socket = requester;

    char* file = options.file;
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
        fprintf(stderr,"Failed to open classify file %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    while ((bytes_read=fread(buf,1,1024,fp)) > 0){
        if(!csv_parse(&p,buf,bytes_read,field_parsed,row_parsed,&data)){
            fprintf(stderr, "Failed to parse file: %s\n",csv_strerror(csv_error(&p)));
        }
    }
    csv_fini(&p,field_parsed,row_parsed,&data);
    //fini took care of freeing the plaintexts
    csv_free(&p);
    free(data.texts);

    

    sleep (2);
    zmq_close (requester);
    zmq_ctx_destroy (context);
    return 0;
}

