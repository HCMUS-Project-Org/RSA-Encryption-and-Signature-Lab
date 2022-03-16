#include <stdio.h>
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

void Task3_Decrypt(BIGNUM *n, BIGNUM *d, BIGNUM *c)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *m = BN_new();

	// m = c^d mod n
	BN_mod_exp(m, c, d, n, ctx);

	char *m_hexstr = BN_bn2hex(m);

	char result[1000];
	textFromHexString(m_hexstr, result);

	printf("Decrypted msg:\n");
	printBN("> Hex format:", m);
	printf("> ASCII format: %s\n", result);
}

int main()
{
	BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *c = BN_new();
	BIGNUM *m = BN_new();

	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&c, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

	Task3_Decrypt(n, d, c);

	return 0;
}
