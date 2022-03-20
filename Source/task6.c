#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a)
{
	// Convert the BIGNUM to number string
	char *number_str = BN_bn2hex(a);
	// Print out the number string
	printf("%s %s\n", msg, number_str);
	// Free the dynamically allocated memory
	OPENSSL_free(number_str);
}

int Task5_VerifySignature(BIGNUM *n, BIGNUM *e, BIGNUM *S, BIGNUM *hash)
{
	BN_CTX *ctx = BN_CTX_new();

	// h2 is h'
	BIGNUM *h2 = BN_new();

	// h' = S^e mod n
	BN_mod_exp(h2, S, e, n, ctx);

	// calc h = string2hex(M)
	//char *h1 = string2hexString(M, strlen(M));

	printBN("> H value:", hash);
	printBN("> H' value:", h2);

	// return compare of h and h'
	return strcmp(BN_bn2hex(hash), BN_bn2hex(h2));
}


int main()
{
	BIGNUM *n = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *s = BN_new();
	BIGNUM *hash = BN_new();

	BN_hex2bn(&n, "C24E1667DDCEBC6AC8375AEC3A30B01DE6D112E8122848CCE829C1B96E53D5A3EB03391ACC7787F601B9D970CCCF6B8DE3E3037186996DCBA6942A4E13D6A7BD04EC0A163C0AEB39B1C4B558A3B6C75625EC3E527AA8E3291607B96E50CFFB5F31F81DBA034A628903AE3E47F20F2791E3142085F8FAE98A35F55F9E994DE76B37EFA4503E44ECFA5A8566079C7E176A55F3178A351EEEE9ACC3754E58557D536B0A6B9B1442D7E5AC0189B3EAA3FECFC02B0C84C2D85315CB67F0D088CA3AD11773F55F9AD4C5721E7E01F19830632AAAF27A2DC5E2021A86E5323E0EBD11B4CF3C93EF1750109E43C2062AE00D68BED3888B4A658C4AD4C32E4C9B55F486E5");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&s, "9580d7f82ad15a90f9b1a2347bb284bbff1e968bed8dffd1c66ccedf8f0befca0f47c0c4527c0b8bf7ed1c409dc8ec3dd1fdd85c00d6aff31bb7e1f48ec09eb77a61e8f2508e94ed90ad0d919c3c4752494cdeb0ef1abc3bbfa254a1c1beb1fffab1da5cd73cf9e78a67077a95470de930f886ef842ca126faaf892812d45838a4de0f959214638e7171578933700bc913f64409b96bc3d305b5a683bf9f179f411746169a54679d4f67fa2a177ab102da33f49bd296fa4f1aa47afe47617112b4eb608505b32e8b79e81b7aa697867c0ca29160e42240d33a055d364319354f27285f55075ececac261f24db3b871bb8afad9978f67d87db0e8c3c6acf092d1");
	BN_hex2bn(&hash, "4a8f4eb394cec0c47f8d9ff64b1341d7a870ea1c660524017433629be2f32171");

	if (Task5_VerifySignature(n, e, s, hash) == 0)
		printf("\n>> This signature is indeed Alice's\n");
	else
		printf("\n>> This signature is NOT indeed Alice's\n");

	return 0;
}