#include <openssl/bn.h>
#include <stdio.h>

void printBN(char *msg, BIGNUM *a)
{
	// Convert the BIGNUM to number string
	char *number_str = BN_bn2hex(a);
	// Print out the number string
	printf("%s %s\n", msg, number_str);
	// Free the dynamically allocated memory
	OPENSSL_free(number_str);
}

BIGNUM *Task1(BIGNUM *p, BIGNUM *q, BIGNUM *e)
{
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *d = BN_new();
	BIGNUM *p_1 = BN_new();
	BIGNUM *q_1 = BN_new();
	BIGNUM *piN = BN_new();

	BIGNUM *one = BN_new();
	BN_hex2bn(&one, "1");

	// find pi(n)
	BN_sub(p_1, p, one);
	BN_sub(q_1, q, one);
	BN_mul(piN, p_1, q_1, ctx);

	// find d: d*e mod piN = 1
	BN_mod_inverse(d, e, piN, ctx);

	return d;
}

int main()
{
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *d = BN_new();

	// init p, q, e's data
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e, "0D88C3");

	// calc d
	d = Task1(p, q, e);

	printBN("> Key d =", d);

	return 0;
}
