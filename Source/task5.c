#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

char *string2hexString(char *input, int len)
{
	char *output = malloc(len * 2 + 1);
	int loop;
	int i;

	i = 0;
	loop = 0;

	while (input[loop] != '\0')
	{
		sprintf((char *)(output + i), "%02X", input[loop]);
		loop += 1;
		i += 2;
	}
	//insert NULL at the end of the output string
	output[i++] = '\0';

	return output;
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

	// h2 is h'
	BIGNUM *h2 = BN_new();

	// h' = S^e mod n
	BN_mod_exp(h2, S, e, n, ctx);

	// calc h = string2hex(M)
	char *h1 = string2hexString(M, strlen(M));

	printf("> H value : %s\n", h1);
	printBN("> H' value:", h2);

	// return compare of h and h'
	return strcmp(h1, BN_bn2hex(h2));
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
