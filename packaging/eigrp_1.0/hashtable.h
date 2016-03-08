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

#include <stdbool.h>

#ifndef HASHTABLE_H_
#define HASHTABLE_H_

typedef struct _list_t_ {
	int key;
	void** value;
	struct _list_t_ *next;
} list_t;

typedef struct _hash_table_t_ {
	int size;
	int real_size;
	list_t **table;
} hash_table_t;

#endif

hash_table_t *create_hash_table(int size);
void *hashtable_getitem(hash_table_t *hashtable, int key);
unsigned int inner_hash(hash_table_t *hashtable, int key);
bool hashtable_removeitem(hash_table_t *hashtable, int key);
int hashtable_additem(hash_table_t *hashtable, void* , int key);
void hashtable_free(hash_table_t *hashtable);
unsigned long hash(char *str);
unsigned int hash_unsigned(unsigned char *str);
