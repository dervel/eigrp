#define _GNU_SOURCE
#include <crypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){

	char *encrypted_password = "$1$mERr$Pjdsd8JUMSJ71vHdU2bLe1";

	char *salt_end = strrchr(encrypted_password,'$');

	int len = salt_end - encrypted_password + 1;

	printf("Len:%d\n",len);

	char *salt = "$1$mERr$";
	char *password = "kappa";

	struct crypt_data data;
	data.initialized = 0;

	char *result = crypt_r(password,salt,&data);

	printf("Result:%s\n",result);
	return 0;
}
