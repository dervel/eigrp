#define _GNU_SOURCE
#include <crypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/hashtable.h"
#include "../src/utils.h"

int main(){

	hash_table_t *table = create_hash_table(10);

	char *name = "Mike";
	char *name1 = "George";
	char *name2 = "Kotol";

	hashtable_additem(table, name , hash(name));
	hashtable_additem(table, name1 , hash(name1));
	hashtable_additem(table, name2 , hash(name2));

	char *test = "George";

	char *ptr = hashtable_getitem(table, hash(test));

	printf("Hashtable Test - Name (Should be George): %s\n",ptr);

	bool result = equals(ptr,test);
	free(table);

	if(result) return 0;
	else return -1;
}
