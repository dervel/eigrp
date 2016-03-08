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

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include "collection.h"
#include "hashtable.h"

void *next(hash_collection* collection){

	if(collection->table == NULL)return NULL;

	if(collection->next != NULL){
		collection->current = collection->next;
		collection->next = collection->next->next;
		return collection->current->value;
	}

	/*if(collection->current != NULL && collection->current->next != NULL){
		collection->current = collection->current->next;
		return collection->current->value;
	}*/

	int i;	
	for(i=collection->table_index;i<collection->table->size;i++){
		if(collection->table->table[i] == NULL)
			continue;

		collection->current = collection->table->table[i];
		collection->next = collection->current->next;
		collection->table_index = i+1;
		return collection->current->value;

		
	}
	return NULL;
}

void prepare_hashcollection(hash_collection *col, hash_table_t *table){
	col->table = table;
	col->table_index = 0;
	col->current = NULL;
	col->next = NULL;
}
