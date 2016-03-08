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
#include <string.h>

#include "vector.h"

void vector_init(vector *vector){
	vector->size = 0;
	vector->capacity = 0;
	vector->data = NULL;
}

void vector_empty(vector *vector){
	free(vector->data);
	
	vector->size = 0;
	vector->capacity = 0;
	vector->data = NULL;
}

void vector_add(vector *vector, void *value){
	if(vector->capacity == 0) {
		vector->capacity = VECTOR_INITIAL_CAPACITY;
		vector->data = malloc(sizeof(void*)* vector->capacity);
		memset(vector->data, '\0', sizeof(void) * vector->capacity);
	}

	if(vector->size >= vector->capacity){
		vector->capacity *= 2;
		vector->data = realloc(vector->data, sizeof(void*) * vector->capacity);
	}

	vector->data[vector->size] = value;
	vector->size++;
}

void vector_replace(vector *vector, int index, void *value){
	if(index >= vector->size)
		return;

	memcpy(vector->data[index],value, sizeof(void*));
}

void *vector_get(vector *vector, int index){
	if(index >= vector->size || index < 0){
		return NULL;
	}
	return vector->data[index];
}

void vector_delete(vector *vector, int index){
	int i,j;
	void **newarr;

	if(index >= vector->size){
		return;
	}

	vector->data[index] = NULL;
	
	newarr = (void**)malloc(sizeof(void*) * vector->size*2);
	for(i=0, j=0; i < vector->size; i++){
		if(vector->data[i] != NULL){
			newarr[j] = vector->data[i];
			j++;
		}
	}

	free(vector->data);
	vector->data = newarr;
	vector->size--;
}

void vector_set(vector *vector, int index, void *value){
	while (index >= vector->size){
		vector_add(vector,0);
	}

	vector->data[index] = value;
}

void vector_free(vector *vector){
	free(vector->data);
}
