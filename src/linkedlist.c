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
#include <stdlib.h>
#include <stdio.h>
#include "linkedlist.h"

void linkedlist_addtail(linkedlist *list ,void* data){
	
	node *new_node;
	new_node = malloc(sizeof(node));
	new_node->data = data;
	new_node->next = NULL;

	if(list->first == NULL){
		list->first = new_node;
		list->last = new_node;
	}else{
		list->last->next = new_node;
		list->last = new_node;
	}
	list->size++;

}

void linkedlist_init(linkedlist *list){
	list->first = NULL;
	list->last = NULL;
	list->size =0;
}

void *linkedlist_getfirst(linkedlist *list){
	if(list->first == NULL){
		return NULL;
	}

	node *ret = list->first;
	list->first = ret->next;
	if(list->first==NULL)
		list->last = NULL;

	void* data = ret->data;
	free(ret);
	list->size--;
	return data;
}

void *linkedlist_peekfirst(linkedlist *list){
	if(list->first == NULL){
		return NULL;
	}

	return list->first->data;
}

bool linkedlist_isempty(linkedlist *list){
	return (list->first == NULL);
}

void linkedlist_free(linkedlist *list){
	
	node *current;
	current = list->first;

	while(current!=NULL){
		node *temp = current;
		current=current->next;
		free(temp);
	}
}
