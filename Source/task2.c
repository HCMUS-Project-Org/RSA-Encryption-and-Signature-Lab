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

BIGNUM *Task2_Encrypt(BIGNUM *n, BIGNUM *e, char *msg)
{
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *m = BN_new();
	BIGNUM *c = BN_new();

	char *hex_msg = string2hexString(msg, strlen(msg));
	BN_hex2bn(&m, hex_msg);

	// c = m^e mod n
	BN_mod_exp(c, m, e, n, ctx);

	return c;
}

int main()
{
	BIGNUM *n = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *c = BN_new();

	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&e, "010001");

	char msg[] = "A top secret!";
	printf("> Message: %s\n", msg);

	c = Task2_Encrypt(n, e, msg);
	printBN("> Encrypted msg:", c);

	return 0;
}
