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

#define VECTOR_INITIAL_CAPACITY 100

#ifndef VECTOR_H_
#define VECTOR_H_

typedef struct vector_{
	int size;
	int capacity;
	void** data;
} vector;

#endif

void vector_init(vector *vector);
void vector_empty(vector *vector);
void vector_add(vector *vector, void*);
void vector_replace(vector *vector, int index, void *value);
void *vector_get(vector *vector, int index);
void vector_set(vector *vector, int index,void*);
void vector_delete(vector *vector, int index);
void vector_free(vector *vector);


