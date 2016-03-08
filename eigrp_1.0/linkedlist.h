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

#ifndef NODE_H_
#define NODE_H_

typedef struct node_{
	void** data;
	struct node_ *next;
} node;

#endif

#ifndef LINKEDLIST_H_
#define LINKEDLIST_H_

typedef struct linkedlist_{
	node *first;
	node *last;
	int size;
} linkedlist;

typedef struct number_container{
	long number;
} number;

#endif

void linkedlist_addtail(linkedlist *list ,void*);
void linkedlist_init(linkedlist *list);
void *linkedlist_getfirst(linkedlist *list);
void *linkedlist_peekfirst(linkedlist *list);
bool linkedlist_isempty(linkedlist *list);
void linkedlist_free(linkedlist *list);
