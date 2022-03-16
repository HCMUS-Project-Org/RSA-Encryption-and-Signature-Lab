#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

void textFromHexString(char *hex, char *result)
{
	char text[20] = {0};
	int tc = 0;

	for (int k = 0; k < strlen(hex); k++)
	{
		if (k % 2 != 0)
		{
			char temp[3];
			sprintf(temp, "%c%c", hex[k - 1], hex[k]);
			int number = (int)strtol(temp, NULL, 16);
			text[tc] = (char)number;

			tc++;
		}
	}
	strcpy(result, text);
}

void printBN(char *msg, BIGNUM *a)
{
	// Convert the BIGNUM to number string
	char *number_str = BN_bn2hex(a);
	// Print out the number string
	printf("%s %s\n", msg, number_str);
	// Free the dynamically allocated memory
	OPENSSL_free(number_str);
}

int Task5_VerifySignature(BIGNUM *n, BIGNUM *e, BIGNUM *S, char *M)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *h = BN_new();

	// h = S^e mod n
	BN_mod_exp(h, S, e, n, ctx);

	char *h_hexstr = BN_bn2hex(h);
	char result[1000];
	textFromHexString(h_hexstr, result);

	printf("H' value:\n");
	printf("> Hex format: %s\n", h_hexstr);
	printf("> ASCII format: %s\n", result);
	printf("> Alice's message: %s\n", M);

	return strcmp(M, result);
}

int main()
{
	BIGNUM *n = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *S = BN_new();
	char M[] = "Launch a missile.";

	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

	if (Task5_VerifySignature(n, e, S, M) == 0)
		printf("\n>> This signature is indeed Alice's\n");
	else
		printf("\n>> This signature is NOT indeed Alice's\n");

	return 0;
}
