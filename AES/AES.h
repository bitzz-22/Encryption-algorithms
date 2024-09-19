#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

struct CIPHER{
	uint32_t* round_keys;
	uint8_t* state;
	uint8_t Nk;
	uint8_t Nr;
};

static const uint32_t Rconj[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0xed000000, 0x9a000000
};

static const uint8_t SBox_table[256] = {
 /* 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t INV_SBox_table[256] = {
 /* 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};


uint8_t xTimes(uint8_t a);

uint8_t mul_term(uint8_t a, uint8_t target);

uint8_t mul_term(uint8_t a, uint8_t target);

uint8_t GF_add(uint8_t a, uint8_t b);

uint8_t GF_mul(uint8_t b, uint8_t c);

uint8_t* mat_mul(uint8_t* matrix, uint8_t* word);

uint8_t SBox(uint8_t byte);

uint8_t INV_SBox(uint8_t byte);

void LOAD_INPUT(uint8_t* input,uint8_t* DESTINATION);

uint32_t ROT_Word(uint32_t word);

uint32_t SUBWORD(uint32_t word);

uint8_t* pad_string(char* data,int* dataSize, int padding_scheme);

void print_state(uint8_t* state);

uint8_t* return_cipher(uint8_t* state);

void transpose(uint8_t* round);

void ADD_ROUND_KEY(uint8_t* state,uint32_t* round);

void SUBBYTES(uint8_t* state);

void SUBBYTES(uint8_t* state);

void SHIFTROWS(uint8_t* state);

void MIXCOLUMN(uint8_t* state);

void INVSHIFTROW(uint8_t* state);

void INVSUBBYTES(uint8_t* state);

void INVMIXCOLUMNS(uint8_t* state);

void KEYEXPANSION(struct CIPHER* ci,uint8_t* key);

uint8_t* CIPHER(struct CIPHER* ci,uint8_t* input);

uint8_t* INVCIPHER(struct CIPHER* ci,uint8_t* input);

uint8_t* ENCRYPT(uint8_t* data, int* dataSize , uint8_t* key , int keySize , int padding_scheme);

uint8_t* DECRYPT(uint8_t* data, int* dataSize , uint8_t* key , int keySize , int padding_scheme);
	






uint8_t xTimes(uint8_t a){
    if(a>>7==0){
        return a<<1;
    }
    return (a<<1)^0b00011011;
}

uint8_t mul_term(uint8_t a, uint8_t target){

    while(target!=0x01){
        a=xTimes(a);
        target>>=1;
    }

    return a;
}

uint8_t GF_add(uint8_t a, uint8_t b){
	return (a^b);
}

uint8_t GF_mul(uint8_t b, uint8_t c){
    uint8_t product=0x00;
    uint16_t mask=0x01;
    while(mask<=0x80){
        if((c & mask) == mask){
            product^=mul_term(b,mask);
        }
        mask<<=1;  
    }
    return product;
}

uint8_t* mat_mul(uint8_t* matrix, uint8_t* word){
	uint8_t* result=(uint8_t*)malloc(4*sizeof(uint8_t));
	for (int i = 0; i < 4; i++){

		result[i]=GF_mul(word[0],*(matrix+(4*i)+0))^
			 GF_mul(word[1],*(matrix+(4*i)+1))^
			 GF_mul(word[2],*(matrix+(4*i)+2))^
			 GF_mul(word[3],*(matrix+(4*i)+3));
	}

	return result;
}

uint8_t SBox(uint8_t byte){
	return SBox_table[byte];
}

uint8_t INV_SBox(uint8_t byte){
	return INV_SBox_table[byte];
}

void LOAD_INPUT(uint8_t* input,uint8_t* DESTINATION){
	for(int r = 0 ; r < 4; r++){
		for(int c = 0 ; c < 4; c++){
			DESTINATION[4*r+c]=input[4*c+r];
		}
	}
}

uint32_t ROT_Word(uint32_t word){
    uint8_t temp= *(((uint8_t*)(&word))+3);
    return (word<<8) | (uint32_t)(temp);
}

uint32_t SUBWORD(uint32_t word){
    uint8_t* byte_ptr=(uint8_t*)&word;
    for (int i = 0; i < 4; i++){
        *(byte_ptr+i)=SBox_table[*(byte_ptr+i)];
    }
    return word;
}

uint8_t* pad_string(char* data,int* dataSize, int padding_scheme){
	uint64_t length = strlen(data);

	uint8_t padding = 16 - (length % 16);
	
	*dataSize = length + padding; 
	uint8_t* buffer = (uint8_t*)malloc(sizeof(uint8_t)*(*dataSize));
	int buffer_index=0;

	// Putting the data in...
	for(buffer_index;buffer_index<length;buffer_index++){
		buffer[buffer_index]=data[buffer_index];
	}

	uint8_t counter=0;
	switch(padding_scheme){
		case 0:    //      PKCS#7- (<data> 03 03 03)
			// Padding the data with 0s until its length is multiple of 16
			for(buffer_index;buffer_index<(*dataSize);buffer_index++){
				buffer[buffer_index]=padding;
			}
			break;

		case 1:    //      ANSI X9.23   (<data> 00 00 00 04)
			// Padding the data with 0s until its length is multiple of 16-1
		
			for(buffer_index;buffer_index<(*dataSize)-1;buffer_index++){
				buffer[buffer_index]=0x00;
				counter++;
			}
			//Putting the number of padding bits added
			buffer[buffer_index]=counter+1;
			break;

		case 2:    //      ISO/IEC 7816-4    (<data> 80 00 00 00)
			//Putting bit 1 after the data
			buffer[buffer_index++]=0x80;

			//Padding the rest of data with 0
			for(buffer_index;buffer_index<(*dataSize);buffer_index++){
				buffer[buffer_index]=0x00;
			}
			break;

		case 3:    //      Random     (<data> 57 84 92 04)

			//Putting random bytes  
			for(buffer_index;buffer_index<(*dataSize)-1;buffer_index++){
				buffer[buffer_index]=rand();
				counter++;
			}
			//Putting the number of padding bits added
			buffer[buffer_index]=counter+1;
			
			break;
	}
	

	return buffer;
}

void print_state(uint8_t* state){
	printf("\n");
	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 4; j++){
			printf("%.02x ",state[4*i+j]);
		}
		printf("\n");
	}
}

uint8_t* return_cipher(uint8_t* state){
	uint8_t* state_t=(uint8_t*)malloc(16);
	for(int row = 0 ; row < 4; row++){
		for(int col = 0 ; col < 4; col++){
			state_t[4*row+col]=(state)[4*col+row];
		}
	}
	// free(*state);
	return state_t;
}

void transpose(uint8_t* round){
	uint8_t* temp_round=(uint8_t*)malloc(16);
	for(int row = 0 ; row < 4; row++){
		for(int col = 0 ; col < 4 ; col++){
			*(temp_round+(4*row+col))=*(round+(4*col+(3-row)));
		}
	}

	for(int row = 0 ; row < 4; row++){
		for(int col = 0 ; col < 4; col++){
			*(round+(4*row+col))=*(temp_round+(4*row+(3-col)));
		}
	}
	free(temp_round);
}

void ADD_ROUND_KEY(uint8_t* state,uint32_t* round){

	// the round key is store in the wrong endinness 
	// because it is a word and not a byte array,
	// hence the word is read backward to correct for it.
	for (int row = 0; row < 4; row++){
		uint8_t* round_byte=((uint8_t*)(round+row))+3;

		for(int column = 0; column < 4; column++){
			state[4*row+column]=state[4*row+column] ^ (*round_byte--);
		}
	}
}

void SUBBYTES(uint8_t* state){
	for (int i = 0; i < 16; i++)
	{
		state[i]=SBox(state[i]);
	}
}

void SHIFTROWS(uint8_t* state){
	for (int row = 1; row < 4; row++){
		uint32_t temp=*(((uint32_t*)state)+row);
		for (int i = 4; i > row; i--)
		{
			temp=ROT_Word(temp);
		}

		for (int i = 3; i >= 0; i--)
		{
			*(state+(4*row+i))=*((uint8_t*)(&temp)+i);
		}
	}
}

void MIXCOLUMN(uint8_t* state){
	uint8_t matrix[16]={0x02,0x03,0x01,0x01,
						0x01,0x02,0x03,0x01,
						0x01,0x01,0x02,0x03,
						0x03,0x01,0x01,0x02};

	for(int col = 0 ; col < 4; col++){
		uint64_t temp = 0;
		for(int row = 0 ; row < 4; row++){
			*((uint8_t*)(&temp)+row)=state[4*row+col];
		}
		uint8_t* t1=mat_mul(matrix,(uint8_t*)(&temp));
		for(int row = 0 ; row < 4; row++){
			state[4*row+col]=*(t1+row);
		}
		free(t1);
		t1=NULL;
	}
}

void INVSHIFTROW(uint8_t* state){
	for (int row = 1; row < 4; row++){
		uint32_t temp=*(((uint32_t*)state)+row);
		for (int i = 0; i < row; i++)
		{
			temp=ROT_Word(temp);
		}

		for (int i = 3; i >= 0; i--)
		{
			*(state+(4*row+i))=*((uint8_t*)(&temp)+i);
		}
	}
}

void INVSUBBYTES(uint8_t* state){
	for (int i = 0; i < 16; i++)
	{
		state[i]=INV_SBox(state[i]);
	}
}

void INVMIXCOLUMNS(uint8_t* state){
	uint8_t matrix[16]={
		0x0e, 0x0b, 0x0d, 0x09,
		0x09, 0x0e, 0x0b, 0x0d,
		0x0d, 0x09, 0x0e, 0x0b,
		0x0b, 0x0d, 0x09, 0x0e,
	};

	for(int col = 0 ; col < 4; col++){
		uint64_t temp = 0;
		for(int row = 0 ; row < 4; row++){
			*((uint8_t*)(&temp)+row)=state[4*row+col];
		}
		uint8_t* t1=mat_mul(matrix,(uint8_t*)(&temp));
		for(int row = 0 ; row < 4; row++){
			state[4*row+col]=*(t1+row);
		}
		free(t1);
		t1=NULL;
	}
}

void KEYEXPANSION(struct CIPHER* ci,uint8_t* key){
	uint8_t i=0;
	uint32_t* w=(uint32_t*)malloc(sizeof(uint32_t)*(4*((ci->Nr)+1)));
	while(i<ci->Nk){
		uint8_t* byte_ptr=(uint8_t*)&w[i];
		for (int b = 3; b >= 0; b--){	
			*(byte_ptr)=key[4*i+b];
			byte_ptr++;

		}
		i++;
	}

	while(i< 4*((ci->Nr)+1)){
		uint32_t temp=w[i-1];
		if(i%(ci->Nk)==0){
			temp= SUBWORD(ROT_Word(temp)) ^ Rconj[i/(ci->Nk)-1];
		}
		else if(ci->Nk >6 && i%ci->Nk==4){
			temp=SUBWORD(temp);
		}
		w[i]= w[i-(ci->Nk)] ^ temp;
		i++;

	}

	// transposing the round_keys because the 
	// "state is transposed(idk why)" because thats supid
	// why did the algorithm take the input rows and place it into columns
	for (int j = 0; j < (ci->Nr+1); j++){	
		transpose((uint8_t*)&w[4*j]);
	}
	ci->round_keys=w;
}

uint8_t* CIPHER(struct CIPHER* ci,uint8_t* input){

	uint8_t* state=(uint8_t*)malloc(16);
	
	LOAD_INPUT(input,state);

	ADD_ROUND_KEY(state,&ci->round_keys[0]);

	for (int round = 1; round < ci->Nr; ++round)
	{
		SUBBYTES(state);

		SHIFTROWS(state);

		MIXCOLUMN(state);

		ADD_ROUND_KEY(state,&ci->round_keys[4*round]);

	}
	SUBBYTES(state);
	SHIFTROWS(state);

	ADD_ROUND_KEY(state,&ci->round_keys[4*(ci->Nr)]);
	ci->state=state;

	return return_cipher(state);
	// free(state);
}

uint8_t* INVCIPHER(struct CIPHER* ci,uint8_t* input){

	uint8_t* state=(uint8_t*)malloc(16);

	LOAD_INPUT(input,state);

	ADD_ROUND_KEY(state,&ci->round_keys[4*(ci->Nr)]);

	for(int round=ci->Nr-1;round>=1;round--){
		INVSHIFTROW(state);

		INVSUBBYTES(state);

		ADD_ROUND_KEY(state,&ci->round_keys[4*round]);

		INVMIXCOLUMNS(state);

	}
	INVSHIFTROW(state);
	INVSUBBYTES(state);
	ADD_ROUND_KEY(state,&ci->round_keys[0]);

	ci->state=state;
	return return_cipher(state);
}

uint8_t* ENCRYPT(uint8_t* data, int* dataSize , uint8_t* key , int keySize , int padding_scheme){
	struct CIPHER ci;

	// int dataSize;
	uint8_t* padded=pad_string(data,dataSize,padding_scheme);

	uint8_t* encrypted_buffer=(uint8_t*)malloc(*dataSize);

	ci.Nk=keySize/4;

	switch(keySize){
		case 16:
			ci.Nr=10;
			break;
		case 24:
			ci.Nr=12;
			break;
		case 32:
			ci.Nr=14;
			break;
	};

	KEYEXPANSION(&ci,key);

	// printf("%d",dataSize);
	for (int i = 0; i < *dataSize/16; i++){		
		uint8_t* tmp=CIPHER(&ci,padded+(16*i));
		for (int j = 0; j < 16; j++)
		{
			encrypted_buffer[16*i+j]=tmp[j];
		}

	}
		
	return encrypted_buffer;
}

uint8_t* DECRYPT(uint8_t* data, int* dataSize , uint8_t* key , int keySize , int padding_scheme){
	struct CIPHER ci;

	ci.Nk=keySize/4;

	uint8_t* decrypted_buffer=(uint8_t*)malloc(*dataSize);

	switch(keySize){
		case 16:
			ci.Nr=10;
			break;
		case 24:
			ci.Nr=12;
			break;
		case 32:
			ci.Nr=14;
			break;
	};

	KEYEXPANSION(&ci,key);
	for (int i = 0; i < *dataSize/16; i++){		
		uint8_t* tmp=INVCIPHER(&ci,data+(16*i));
		for (int j = 0; j < 16; j++)
		{
			decrypted_buffer[(16*i)+j]=tmp[j];
		}
		
	}


	return decrypted_buffer;
}



