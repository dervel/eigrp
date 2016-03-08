
#include <stdio.h>

#include "utils.h"

int main(){

	char *mask = "0.0.0.255";
	int prefix = wildcard_to_prefix(mask);
	printf("Prefix of %s is %d\n",mask, prefix);
	mask = "255.255.0.0";
	prefix = wildcard_to_prefix(mask);
	printf("Prefix of %s is %d\n",mask, prefix);
	mask = "kappa";
	prefix = wildcard_to_prefix(mask);
	printf("Prefix of %s is %d\n",mask, prefix);
	mask = "254.255.0.0";
	prefix = wildcard_to_prefix(mask);
	printf("Prefix of %s is %d\n",mask, prefix);
	return 0;

}
