
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "hashtable.h"

int main(){
	hash_table_t *table = create_hash_table(100);

	char *string = "1234567890";
	char *string1 = "abcdefg";

	hashtable_additem(table,string,15);
	hashtable_additem(table,string1,20);

	char *res = hashtable_getitem(table,20);
	printf("%s\n",res);
	char *res1 = hashtable_getitem(table,15);
	printf("%s\n",res1);

	hashtable_removeitem(table,20);

	char *s = hashtable_getitem(table,20);

	if(s == NULL){
		printf("Is NULL\n");
	}else{
		printf("s:%s\n",s);
	}
	
	hashtable_free(table);
}
