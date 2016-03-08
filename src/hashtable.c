/*

	eigrp - A routing daemon for the eigrp protocol
	Copyright (C) 2015 Paraskeuas Karahatzis

	This program is free software: you can redistribute it and/or modify it under the terms of the
	GNU General Public License as published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
	even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
	General Public License for more details.

	You should have received a copy of the GNU General Public License along with this program. If not,
	see <http://www.gnu.org/licenses/>. 

	dervelakos.madlax@gmail.com

*/

#include "stdlib.h"
#include "hashtable.h"

hash_table_t *create_hash_table(int size){
	hash_table_t *new_table;

	if(size < 1) return NULL;

	if((new_table = malloc(sizeof(hash_table_t))) == NULL)
		return NULL;

	if((new_table->table = malloc(sizeof(list_t *) * size)) == NULL)
		return NULL;

	int i;
	for(i=0; i<size;i++) new_table->table[i] = NULL;

	new_table->size = size;
	new_table->real_size = 0;

	return new_table;
}

unsigned int inner_hash(hash_table_t *hashtable, int key){
	unsigned int hashval;

	hashval = key;

	return hashval % hashtable->size;
}

void *hashtable_getitem(hash_table_t *hashtable, int key){
	list_t *list;
	unsigned int hashval = inner_hash(hashtable, key);

	for(list = hashtable->table[hashval]; list != NULL; list = list->next){
		if(list->key == key)
			return list->value;
	}

	return NULL;
}

bool hashtable_removeitem(hash_table_t *hashtable, int key){

	unsigned int hashval = inner_hash(hashtable, key);

	list_t *list = hashtable->table[hashval];

	if(list == NULL) return false;

	if(list->key == key){
		hashtable->table[hashval]=list->next;
		free(list);
		hashtable->real_size--;
		return true;
	}

	for(; list != NULL; list = list->next){
		if(list->next != NULL && list->next->key == key){
			list_t *to_be_removed = list->next;

			list->next = list->next->next;
			
			free(to_be_removed);
			hashtable->real_size--;
			return true;
		}
	}

	return false;
	
}

int hashtable_additem(hash_table_t *hashtable, void* value, int key){
	list_t *new_list, *current_list;
	unsigned int hashval = inner_hash(hashtable, key);

	if((new_list = malloc(sizeof(list_t))) == NULL) return 1;
	
	current_list = hashtable_getitem(hashtable, key);
	if(current_list != NULL) return 2;

	new_list->value = value;
	new_list->key = key;
	new_list->next = hashtable->table[hashval];
	hashtable->table[hashval] = new_list;
	hashtable->real_size++;

	return 0;
}

void hashtable_free(hash_table_t *hashtable){
	int i;
	list_t *list, *temp;

	if(hashtable == NULL) return;

	for(i=0;i<hashtable->size;i++){
		list = hashtable->table[i];
		while(list != NULL){
			temp = list;
			list = list->next;
			free(temp);
		}
	}

	free(hashtable->table);
	free(hashtable);
}

/*unsigned long hash(char *str){*/
/*	unsigned long hashval;*/
/*	*/
/*	for(hashval=0 ; *str != 0 ; str++){*/
/*		hashval = *str + (hashval << 5) - hashval;*/
/*	}*/

/*	return hashval;*/

/*}*/

unsigned long hash(char *str){
	unsigned long hash = 5381;
	int c=0;

	while((c = *str++) != 0){
		hash = ((hash << 5) + hash) +c;
	}
	return hash;
}

unsigned int hash_unsigned(unsigned char *str){
	unsigned int hashval;
	
	for(hashval=0 ; *str != 0 ; str++){
		hashval = *str + (hashval << 5) - hashval;
	}

	return hashval;

}
