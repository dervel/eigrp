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

#include "hashtable.h"

#ifndef COLLECTION_H_
#define COLLECTION_H_

typedef struct collection{
	int table_index;
	list_t *current;
	list_t *next;
	hash_table_t *table;
} hash_collection;

#endif

void *next(hash_collection* collection);
void prepare_hashcollection(hash_collection *col, hash_table_t *table);
