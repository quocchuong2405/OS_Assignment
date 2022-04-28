#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

int empty(struct queue_t * q) {
	return (q->size == 0);
}

void enqueue(struct queue_t * q, struct pcb_t * proc) {
	/* TODO: put a new process to queue [q] */
	if (q->size < MAX_QUEUE_SIZE) 
		q->proc[q->size++] = proc;
	
}

struct pcb_t * dequeue(struct queue_t * q) {
	/* TODO: return a pcb whose prioprity is the highest
	 * in the queue [q] and remember to remove it from q
	 * */
	if (empty(q)) return NULL;

    int highest = 0;
    for (int i = 1; i < q->size; i++) {
        if (q->proc[i]->priority > q->proc[highest]->priority) {
            highest = i;
        }
    }
    struct pcb_t * res = q->proc[highest];
    for (int i = highest + 1; i < q->size; i++) {
        q->proc[i - 1] = q->proc[i];
    }
    q->size--;
    return res;
}

