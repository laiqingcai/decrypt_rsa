#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/base64.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"

#define mbedtls_printf       printf
#define mbedtls_exit         exit


#define DEBUG_INFO(fmt, args...) printf("\033[33m[%s:%s:%d]\033[0m "#fmt"\r\n", __FILE__,__FUNCTION__, __LINE__, ##args)

#define KEY_SIZE 1024
#define BUFFER_SIZE 1024
#define EXPONENT 65537
//公钥
uint8_t rsa_n[BUFFER_SIZE];

uint8_t rsa_e[BUFFER_SIZE];
uint8_t rsa_d[BUFFER_SIZE];
uint8_t rsa_p[BUFFER_SIZE];
uint8_t rsa_q[BUFFER_SIZE];
uint8_t rsa_dp[BUFFER_SIZE];
uint8_t rsa_dq[BUFFER_SIZE];
uint8_t rsa_qp[BUFFER_SIZE];

//公钥长度
int RSA_N_Len; 

uint8_t PubKey[1024]; 
char PubPem[2048]={0};

//读取rsa key
int ReadRsaKey(void)
{
    int ret = 0;
    mbedtls_rsa_context rsa;
    FILE *fpriv;

    RSA_N_Len = 0;
	memset(rsa_n , 0 ,BUFFER_SIZE);
	memset(rsa_e , 0 ,BUFFER_SIZE);
	memset(rsa_d , 0 ,BUFFER_SIZE);
	memset(rsa_p , 0 ,BUFFER_SIZE);
	memset(rsa_q , 0 ,BUFFER_SIZE);
	memset(rsa_dp, 0 ,BUFFER_SIZE);
	memset(rsa_dq, 0 ,BUFFER_SIZE);
	memset(rsa_qp, 0 ,BUFFER_SIZE);
    
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    if (( fpriv = fopen("./rsa_priv.txt", "rb")) == NULL)  {
        DEBUG_INFO("fopen rsa file failed\n");
        ret = -1;
        goto exit;
    }
    
     if( ( ret = mbedtls_mpi_read_file( &rsa.N , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.E , 16, fpriv) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.D , 16, fpriv) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.P , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.Q , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.DP, 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.DQ, 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.QP, 16, fpriv ) ) != 0 ) {
        DEBUG_INFO("read rsa file failed\n");
        ret = -1;
        goto exit;
    }

    mbedtls_mpi_write_binary(&rsa.N, rsa_n , BUFFER_SIZE);
	mbedtls_mpi_write_binary(&rsa.E, rsa_e , BUFFER_SIZE);
	mbedtls_mpi_write_binary(&rsa.D, rsa_d , BUFFER_SIZE);
	mbedtls_mpi_write_binary(&rsa.P, rsa_p , BUFFER_SIZE);
	mbedtls_mpi_write_binary(&rsa.Q, rsa_q , BUFFER_SIZE);
	mbedtls_mpi_write_binary(&rsa.DP, rsa_dp ,BUFFER_SIZE);
	mbedtls_mpi_write_binary(&rsa.DQ, rsa_dq, BUFFER_SIZE);
	mbedtls_mpi_write_binary(&rsa.QP, rsa_qp , BUFFER_SIZE);

    RSA_N_Len = (mbedtls_mpi_bitlen(&rsa.N)+7) >> 3;
	memset(PubKey , 0 , BUFFER_SIZE);	
	memcpy(PubKey , &rsa_n[1024-RSA_N_Len] , RSA_N_Len);
	int  n;
    #if 1
	for( n= 1024-RSA_N_Len; n< 1024 ;n++) {
		printf("%02x" , rsa_n[n]);
	}
	printf("\n");
    #endif
    
exit:
    if (fpriv) {
        fclose(fpriv);
    }
    mbedtls_rsa_free(&rsa);
    return ret;
}


//生成或者读取rsa公钥与私钥
int CreateRsaKey(void)
{
    int ret = -1;

    ret = ReadRsaKey();
    if (ret == 0) {
        DEBUG_INFO("ret=%d",ret);
        return ret;
    }

    DEBUG_INFO("ret=%d",ret);
    
	RSA_N_Len = 0;
	memset(rsa_n , 0 ,BUFFER_SIZE);
	memset(rsa_e , 0 ,BUFFER_SIZE);
	memset(rsa_d , 0 ,BUFFER_SIZE);
	memset(rsa_p , 0 ,BUFFER_SIZE);
	memset(rsa_q , 0 ,BUFFER_SIZE);
	memset(rsa_dp, 0 ,BUFFER_SIZE);
	memset(rsa_dq, 0 ,BUFFER_SIZE);
	memset(rsa_qp, 0 ,BUFFER_SIZE);
	mbedtls_rsa_context rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "rsa_genkey";
	mbedtls_entropy_init(&entropy);
	/*
	if((ret = mbedtls_ctr_drbg_init(&ctr_drbg) != 0) {
   
        DEBUG_INFO( " failed ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }
    */
	mbedtls_ctr_drbg_init(&ctr_drbg);
	
	DEBUG_INFO( " ok  . Generating the RSA key [ %d-bit ]...\n", KEY_SIZE);
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
	if ((ret = mbedtls_rsa_gen_key( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, EXPONENT)) != 0) {
		DEBUG_INFO( " failed	! rsa_gen_key returned %d\n\n", ret );
		goto exit;
	}
	
	mbedtls_mpi_write_binary(&rsa.N, rsa_n , BUFFER_SIZE);
	mbedtls_mpi_write_binary(&rsa.E, rsa_e , BUFFER_SIZE);
	mbedtls_mpi_write_binary(&rsa.D, rsa_d , BUFFER_SIZE);
	mbedtls_mpi_write_binary(&rsa.P, rsa_p , BUFFER_SIZE);
	mbedtls_mpi_write_binary(&rsa.Q, rsa_q , BUFFER_SIZE);
	mbedtls_mpi_write_binary(&rsa.DP, rsa_dp ,BUFFER_SIZE);
	mbedtls_mpi_write_binary(&rsa.DQ, rsa_dq, BUFFER_SIZE);
	mbedtls_mpi_write_binary(&rsa.QP, rsa_qp , BUFFER_SIZE);
	RSA_N_Len = (mbedtls_mpi_bitlen(&rsa.N)+7) >> 3;
	memset(PubKey , 0 , BUFFER_SIZE);	
	memcpy(PubKey , &rsa_n[1024-RSA_N_Len] , RSA_N_Len);
	int  n;
	DEBUG_INFO("rsa.N: ");
	for( n= 1024-RSA_N_Len; n< 1024 ;n++) {
		printf("%02x" , rsa_n[n]);
	}
	printf("\n");
	FILE * fpriv = NULL;
	if ((fpriv = fopen("./rsa_key.txt", "wb+")) == NULL) {
        ret = 1;
        goto exit;
    }
	 if( ( ret = mbedtls_mpi_write_file( "N = " , &rsa.N , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "E = " , &rsa.E , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "D = " , &rsa.D , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "P = " , &rsa.P , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "Q = " , &rsa.Q , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "DP = ", &rsa.DP, 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "DQ = ", &rsa.DQ, 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "QP = ", &rsa.QP, 16, fpriv ) ) != 0 )  {
        DEBUG_INFO( " failed  ! mpi_write_file returned %d\n", ret );
        goto exit;
    }
exit:
	if( fpriv != NULL ) {
        fclose( fpriv );
	}
	mbedtls_rsa_free( &rsa );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
	return ret;
}

//rsa 用私钥解密
int RsaDecrypt(const unsigned char *InBuf , unsigned char* OutBuf)
{
	int ret, c;
	size_t i;
	mbedtls_rsa_context rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const unsigned char *pers = "rsa_decrypt";
	ret = 1;
	mbedtls_entropy_init(&entropy);
	/*
	if(( ret = mbedtls_ctr_drbg_init(&ctr_drbg) != 0)  {
        DEBUG_INFO( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }
    */
    mbedtls_ctr_drbg_init(&ctr_drbg);
	
	mbedtls_rsa_init(&rsa , MBEDTLS_RSA_PKCS_V15 , 0);
	mbedtls_mpi_read_binary(&rsa.N , rsa_n , BUFFER_SIZE);
	mbedtls_mpi_read_binary(&rsa.E , rsa_e , BUFFER_SIZE);
	mbedtls_mpi_read_binary(&rsa.D , rsa_d , BUFFER_SIZE);
	mbedtls_mpi_read_binary(&rsa.P , rsa_p , BUFFER_SIZE);
	mbedtls_mpi_read_binary(&rsa.Q , rsa_q , BUFFER_SIZE);
	mbedtls_mpi_read_binary(&rsa.DP , rsa_dp , BUFFER_SIZE);
	mbedtls_mpi_read_binary(&rsa.DQ , rsa_dq , BUFFER_SIZE);
	mbedtls_mpi_read_binary(&rsa.QP , rsa_qp , BUFFER_SIZE);
	rsa.len = (mbedtls_mpi_bitlen(&rsa.N)+7) >> 3;
	DEBUG_INFO("rsa.len: %d\n", rsa.len);


	
	if( ( ret = mbedtls_rsa_pkcs1_decrypt( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &i, InBuf, OutBuf, 1024)) != 0 )
    {
        DEBUG_INFO( " failed\n  ! rsa_pkcs1_decrypt returned %d\n\n", ret );
        goto exit;
    }
    DEBUG_INFO( "The RSA decrypted OutBuf is: '%s'\n\n", OutBuf);
    
exit:
	mbedtls_rsa_free( &rsa );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
	return ret;
}

int MyRsaDecrypt(const unsigned char *InBuf , unsigned char* OutBuf){
	FILE *f;
    int ret = 1;
    //int exit_code = MBEDTLS_EXIT_FAILURE;
    unsigned c;
    size_t i;
    mbedtls_rsa_context rsa;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char result[1024];
    unsigned char buf[512];
    const char *pers = "rsa_decrypt";
    //((void) argv);

    memset(result, 0, sizeof( result ) );

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                        &entropy, (const unsigned char *) pers,
                                        strlen( pers ) );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
                        ret );
        goto exit;
    }

    mbedtls_printf( "\n  . Reading private key from rsa_priv.txt" );
    fflush( stdout );

    if( ( f = fopen( "rsa_priv.txt", "rb" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not open rsa_priv.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_read_file( &N , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &E , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &D , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &P , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &Q , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &DP , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &DQ , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &QP , 16, f ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_file returned %d\n\n",
                        ret );
        fclose( f );
        goto exit;
    }
    fclose( f );

    if( ( ret = mbedtls_rsa_import( &rsa, &N, &P, &Q, &D, &E ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_import returned %d\n\n",
                        ret );
        goto exit;
    }

    if( ( ret = mbedtls_rsa_complete( &rsa ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_complete returned %d\n\n",
                        ret );
        goto exit;
    }

    /*
     * Extract the RSA encrypted value from the text file
     */

	/*
    if( ( f = fopen( "result-enc.txt", "rb" ) ) == NULL )
    {
        mbedtls_printf( "\n  ! Could not open %s\n\n", "result-enc.txt" );
        goto exit;
    }

    i = 0;

    while( fscanf( f, "%02X", (unsigned int*) &c ) > 0 &&
           i < (int) sizeof( buf ) )
        buf[i++] = (unsigned char) c;

    fclose( f );

    if( i != rsa.len )
    {
        mbedtls_printf( "\n  ! Invalid RSA signature format\n\n" );
        goto exit;
    }
    */
    

    /*
     * Decrypt the encrypted RSA data and print the result.
     */
    mbedtls_printf( "\n  . Decrypting the encrypted data" );
    fflush( stdout );

    ret = mbedtls_rsa_pkcs1_decrypt( &rsa, mbedtls_ctr_drbg_random,
                                            &ctr_drbg, MBEDTLS_RSA_PRIVATE, &i,
                                            InBuf, OutBuf, 1024 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_decrypt returned %d\n\n",
                        ret );
        goto exit;
    }

    mbedtls_printf( "\n  . OK\n\n" );

    mbedtls_printf( "The decrypted result is: '%s'\n\n", OutBuf );

    //exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_rsa_free( &rsa );
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
}



//base64解码，rsa私钥解密
int Base64DeAndRsa(const unsigned char *Base64, unsigned char *OutBuf)
{
    int ret = -1;
	size_t num =0;
	char DataOut2[8000]={0};


	
	mbedtls_base64_decode(NULL , 0, &num , Base64 , strlen(Base64));
	ret = mbedtls_base64_decode(DataOut2 , sizeof(DataOut2), &num , Base64 , strlen(Base64));
	if (ret != 0) {
        DEBUG_INFO("base64 decode failed,ret=%d",ret);
        return ret;
    }
    


	printf("Base64 decrypt: '%s'\n", DataOut2);
	DEBUG_INFO( "The Base64 decrypted OutBuf is: '%s'\n\n", DataOut2);
	
	//ret = RsaDecrypt(DataOut2, OutBuf);
	DEBUG_INFO("===1===");
	ret = MyRsaDecrypt(DataOut2, OutBuf);
	DEBUG_INFO("===2===");
	
	return ret;
}


//公钥转换pkcs1输出
void RsaNToPkcs1(char * PemData)
{	 
	char DataOut[1024]={0};
	char PkcsANS[512]={0};
	uint8_t Head[]=  {
		0x30 , 0x81 ,0x9F ,0x30 ,0x0D ,0x06 , 0x09 ,0x2A ,
		0x86 ,0x48 ,0x86 ,0xF7 ,0x0D ,0x01 ,0x01 ,0x01,
		0x05 ,0x00 ,0x03 ,0x81 ,0x8D ,0x00 ,0x30 ,0x81,
		0x89 ,0x02 ,0x81 ,0x81, 0x00
	};
	uint8_t Last[]={0x02 ,0x03 ,0x01, 0x00, 0x01};
	memcpy(PkcsANS , Head , sizeof(Head));
	memcpy(&PkcsANS[sizeof(Head)], PubKey , RSA_N_Len);
	memcpy(&PkcsANS[sizeof(Head)+RSA_N_Len] , Last , sizeof(Last));
	int size = sizeof(Head) + RSA_N_Len + sizeof(Last);
	char Base64[1024]={0} ;
	size_t num = 0;
    //NULL ,num设为0 ，是为了获取num
	mbedtls_base64_encode(NULL , 0, &num, PkcsANS, size);  
	//真正base64编码
	mbedtls_base64_encode(Base64 , sizeof(Base64), &num,  PkcsANS, size); 	
	int n , i =0 ;
	for (n = 0 ; n<  num ; n++) {
	
		if (n!=0 && (n+1)%64 == 0) {
			DataOut[i] = '\n';
			i++;
		}
		DataOut[i]= Base64[n];
		i++;
	}
	sprintf( PemData ,"\n-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" , DataOut);
	DEBUG_INFO("%s" , PemData);
}


//测试
void TestRsa(void)
{
  CreateRsaKey();
  RsaNToPkcs1(PubKey);

  //采用rsa公钥加密base64编码之后的密文，明文是12345678
  unsigned char buf[1024] = "qpkO85wYitHwZ/HTm3+DKZmfVm1jZkjwowMIY3rOsXnj6WMSNSKyCRX6aEOUqDHDX7JlqjPctzHYsMBGQyZ5jvKuiLIjIGDQsZtFWg29iXwSz09jhAdixCmiP6JqfMho9zek5FUydqM9tyMQppv8h3ilM8kiFCXRZ2+76PmhSg0=";

  //unsigned char buf[1024] = "eA+5VlIpqDPSYWXWE1KCcMmHawwhbDTT8OAMbZunsfJzUE40DubcJzqyCAMgaA7XtE8eSPn0y9Fn2Ib4miUz5hjO5UILtlvbjGOq09bzDOTGUR6O9EDegNoej8bbmqSfLPvxjB6EHOJlzc6yVQoocZDAur0KNViQbAUwQKLYKJY=";

  unsigned char OutBuf_test[2048] = {0};
  /*
  MyRsaDecrypt(buf, OutBuf_test);
  DEBUG_INFO("OutBuf_test: %s\n",OutBuf_test);
  printf("OutBuf_test: %s\n",OutBuf_test);
  */


  unsigned char OutBuf[2048] = {0};
  //base64解码，rsa私钥解密
  Base64DeAndRsa(buf,OutBuf);
  //使用rsa私钥解密之后
  DEBUG_INFO("%s",OutBuf);
}

int main(void)
{
   TestRsa();
    
	return 0;
}
