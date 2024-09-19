#include <stdio.h>
#include <stdint.h>
#include "AES.h"

int main(int argc, char const *argv[]){	

	if(0){//(argc==1){
		// show_usage();
	}
	else{
		// struct cmd* CMD = parsecmd(argc,argv);
		unsigned char* data="\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34";
		int dataSize=16;
		
		printf("\nDATA:\t");
		for (int i = 0; i < dataSize; i++)
		{
			printf("%2.2x ",data[i]);
		}

		uint8_t key[16]={0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
		int keySize=16;

		int padding_scheme=0;

		srand(time(NULL)); 
		
		uint8_t* encrypted = ENCRYPT((uint8_t*)data,&dataSize,key,16,padding_scheme);

		uint8_t* decrypted = DECRYPT(encrypted,&dataSize,key,16,padding_scheme);

		printf("\nKEY:\t");
		for (int i = 0; i < keySize; i++)
		{
			printf("%02x ",key[i]);
		}

		printf("\n\nENCRYPTED WITH PADDING:\t");
		for (int i = 0; i < dataSize; i++)
		{
			printf("%02x",encrypted[i]);
		}

		printf("\nDECRYPTED WTIH PADDING:\t");
		for (int i = 0; i < dataSize; i++)
		{
			printf("%02x",decrypted[i]);
		}
		printf("\n");
	}   
	return 0;
}

/*
																	Pending:
																		-cmdline argument support
																		-file input support
																		-CBC Mode

*/


// void show_usage(){
// 	char* USAGE=
// 	"USAGE:  AES.exe <option> -d <data> -k <key> -m <mode> -p <padding>\n\n\n"


// 			"options: encrypt/decrypt\n\n"

// 			"\t-d :- specify data to be encrypted/decrypted\n"
// 			//"\t-D :- specify file where data is stored\n\n"

// 			"\t-k :- key to encrypt/decrypt\n\n"

// 			"MODES:\n\t"
// 				"CBC,ECB\n\n"

// 			"PADDING SCHEMES:\n\t"
// 				"PKCS#7   (<data> 03 03 03)\n\t"
// 				"ANSI X9.23   (<data> 00 00 00 04)\n\t"
// 				"ISO/IEC 7816-4    (<data> 80 00 00 00)\n\t"
// 				"Random     (<data> 57 84 92 04)\n\t\t"
// 			;
// 	printf("%s",USAGE);
// }




// struct cmd* parsecmd(int argc, char const *argv[]){
// 	struct cmd CMD;
// 	int arg_counter=1;
// 	if(argc>=6){
// 		printf("greater than 6 \n");
// 		printf("%s",argv[1]);
// 		if(strcmp(argv[1] , "encrypt") || strcmp(argv[1] , "decrypt") ){
// 			CMD.ed=argv[1];
// 			printf("signal recieved %s\n",argv[1]);
// 			for(int i=2; i < argc; i+=2){

// 				if(strlen(argv[i])==2){
// 					printf("flag %s\n",argv[i]);
// 					if(argv[i][0]=='-'){
// 						switch(argv[i][1]){
// 							case 'd':
// 								CMD.data=argv[i+1];
								
// 								break;
// 							case 'k':
// 								CMD.key=argv[i+1];
// 								break;
// 							// case 'm':
// 							// 	CMD.data=argv[i+1]
// 							// 	break;
// 							case 'p':
// 								CMD.padding=(int)argv[i+1];
// 								break;
// 						}
// 						printf("printf data %s",argv[i+1]);
// 					}
// 					else{break;}
// 				}
// 				else{break;}
// 			}
// 		}
		
		
// 	}
// 	printf("invalid arguments");
// 	show_usage();
// }

// struct cmd{
// 	char* ed;
// 	char* data;
// 	char* key;
// 	int padding;
// };



