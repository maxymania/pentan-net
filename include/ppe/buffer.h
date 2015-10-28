#ifndef PPE_BUFFER_H
#define PPE_BUFFER_H

/*
 * typedef struct{...} ppeBuffer;
 *
 * @brief Buffer Primitive
 *
 * This datastructure enables proper prepending and appending of data to a
 * packet with bounds checking ( to mitigate the risk of buffer-overflows).
 *
 * The essential properties of a buffer are its begin, end, limit, and position:
 * - A buffer's begin is the pointer to the begin of the memory area.
 * - A buffer's end is the pointer to the end of the memory area.
 * - A buffer's position is the pointer to the begin of the content within the
 *   memory area.
 * - A buffer's limit is the pointer to the end of the content within the
 *   memory area.
 * 
 * Invariant: begin <= position <= limit <= end;
 */
typedef struct{
	void* begin;
	void* position;
	void* limit;
	void* end;
} ppeBuffer;

#endif


