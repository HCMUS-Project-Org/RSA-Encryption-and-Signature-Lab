#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>

//function to convert ascii char[] to hex-string (char[])
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

BIGNUM *Task4_RSAsign(BIGNUM *n, BIGNUM *d, char *msg)
{
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *m = BN_new();
	BIGNUM *s = BN_new();

	char *hex_msg = string2hexString(msg, strlen(msg));
	BN_hex2bn(&m, hex_msg);

	// Sign s = h(msg)^d mod n
	BN_mod_exp(s, m, d, n, ctx);

	return s;
}

int main()
{
	BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *s = BN_new();

	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	char msg[] = "I owe you $3000.";
	printf("> Message: %s\n", msg);

	s = Task4_RSAsign(n, d, msg);
	printBN("> Signature:", s);

	return 0;
}
