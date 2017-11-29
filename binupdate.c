/*
 * Copyright (C) 2012 gonzoj
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <dlfcn.h>
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pe.h"

#include "beaengine/BeaEngine.h"

BEA_API int __bea_callspec__ (*bea_disasm) (LPDISASM pDisAsm);

#define bea_disasm_init(dasm) DISASM dasm; memset(&dasm, 0, sizeof(DISASM))

#define bea_disasm_one(dasm, len, buf, size, off) dasm.EIP = off; \
						  dasm.SecurityBlock = (UIntPtr) (buf) + size - dasm.EIP; \
						  len = bea_disasm(&dasm); \
						  if (len == OUT_OF_BLOCK) goto error; \
						  if (len == UNKNOWN_OPCODE) goto error

#define for_each_instruction(dasm, len, buf, size, off) for (dasm.EIP = (UIntPtr) (buf) + (off), dasm.SecurityBlock = (UIntPtr) (buf) + (size) - dasm.EIP, len = bea_disasm(&dasm); \
							len != OUT_OF_BLOCK && len != UNKNOWN_OPCODE && dasm.EIP < (UIntPtr) (buf) + (size); \
							dasm.EIP += len, dasm.SecurityBlock = (UIntPtr) ((buf) + (size) - dasm.EIP), len = bea_disasm(&dasm))

#define for_each_opcode(dasm, len, buf, size, off) for (dasm.EIP = (UIntPtr) (buf) + (off), dasm.SecurityBlock = (UIntPtr) (buf) + (size) - dasm.EIP, len = bea_disasm(&dasm); \
							len != OUT_OF_BLOCK && dasm.EIP < (UIntPtr) (buf) + (size); \
							dasm.EIP += len, dasm.SecurityBlock = (UIntPtr) (buf) + (size) - dasm.EIP, len = bea_disasm(&dasm))

#define HIWORD(x) ((x) & 0xFFFF0000)
#define LOWORD(x) ((x) & 0x0000FFFF)

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))
#define ceildiv(x, y) ((x) % (y) ? ((x) / (y)) + 1 : (x) / (y))

#define array_init(buf, len) buf = NULL; len = 0
#define array_insert(buf, len, type, e) (len)++; buf = (type *) realloc(buf, (len) * sizeof(type)); memcpy((buf) + ((len) - 1), &(e), sizeof(type))
#define array_destroy(buf, len) if (buf) free(buf); buf = NULL; len = 0

#define percent(x, y) ((y) ? ((double) (x) / (double) (y)) * 100 : (double) 0)

#define msleep(ms) usleep((ms) * 1000)

struct function {
	rva offset;
	size_t size;
	struct {
		rva *callee;
		int num;
	} call_site;
};

struct function_tree {
	struct function *function;
	int num;
};

struct binary {
	pe_file *pef;
	pe_section_header *header;
	pe_buffer *section;
	struct function_tree *tree;
};

typedef int (*metric_function)(struct binary *, struct function *, struct binary *, struct function *, double *);

struct metric {
	metric_function *apply;
	char **name;
	int num;
};

#define metric_init(m) (m).apply = NULL; (m).name = NULL; m.num = 0
#define metric_destroy(m) if ((m).apply) free((m).apply); (m).apply = NULL; if ((m).name) free((m).name); (m).name = NULL; (m).num = 0

struct match {
	struct {
		struct function *function;
		struct {
			double total;
			double *metric;
		} quality;
	} *top;
	int n;
	int num;
	pthread_mutex_t mutex;
	struct metric *metric;
};

#define match_init(m, n) (m).num = n

struct workload {
	struct function_tree *subtree;
	int *processed;
	int num;
	pthread_mutex_t mutex;
};

struct thread_env {
	struct {
		struct binary *bin;
		struct function *function;
	} ref;
	struct binary *bin;
	struct workload *workload;
	void **arg;
};

#define get_thread_arg(env, i, type) ((type*)env->arg)[i]

typedef void * (*thread_pool_worker)(struct thread_env *);

/* options */

#define FUNCTION_ALIGNMENT 0x10

#define align(x) ((x) % FUNCTION_ALIGNMENT ? (x) + FUNCTION_ALIGNMENT - ((x) % FUNCTION_ALIGNMENT) : x)

#define is_aligned(x) !((x) % FUNCTION_ALIGNMENT)

#define INSTR_PAD 0xCC

#define WORKLOAD_NUM 50

#define THREADS 4

#define MAX_SIZE_DIFF 0.4

#define MIN_CALLER_SIZE 200

#define MAX_CALLER_NUM_DIFF 0.25

#define CALLER_NUM_SENSITIVITY 50

#define MAX_CALLEE_NUM_DIFF 0.25

#define FOLLOW_SWITCH 1

#define FIX_CALL_SITE 0

#define PROGRESS_BAR_STEP 2

void function_tree_destroy(struct function_tree *tree) {
	int i;
	for (i = 0; i < tree->num; i++) {
		if (tree->function[i].call_site.callee) free(tree->function[i].call_site.callee);
	}

	if (tree->function) free(tree->function);
}

void match_destroy(struct match *match) {
	int i;
	for (i = 0; i < match->num; i++) {
		if (match->top[i].quality.metric) free(match->top[i].quality.metric);
	}

	if (match->top) free(match->top);
}

void metric_add(struct metric *metric, metric_function f, char *name) {
	metric->num++;
	metric->apply = (metric_function *) realloc(metric->apply, metric->num * sizeof(metric_function));
	metric->apply[metric->num - 1] = f;
	metric->name = (char **) realloc(metric->name, metric->num * sizeof(char *));
	metric->name[metric->num - 1] = name;
}

char * get_function_name(pe_file *pef, pe_section_header *header, struct function *f, char *buf) {
	char name[24];
	snprintf(name, 24, "sub_%08lX", (unsigned long) pe_section_base(pef, header) + f->offset);
	memcpy(buf, name, strlen(name));
	return buf;
}

struct function * get_function(struct function_tree *tree, rva offset) {
	int i;
	for (i = 0; i < tree->num; i++) {
		if (tree->function[i].offset == offset) {
			return tree->function + i;
		} else if (offset > tree->function[i].offset && offset < tree->function[i].offset + tree->function[i].size) {
			printf("warning: offset %X is not start of function\n", offset);
			return tree->function + i;
		}
	}

	return NULL;
}

void progress_bar(int *processed, int num, int total, int *s, int block) {
	if (block) {
		printf("progress: [ ");
		fflush(stdout);
	}

	int p;
	do  {
		p = 0;

		int i;
		for (i = 0; i < num; i++) {
			p += processed[i];
		}

		double d = percent(p, total);
		int b = ceil(d);
		if (b > 100) b = 100;

		while (*s < (b / PROGRESS_BAR_STEP)) {
			(*s)++;
			printf("-");
			fflush(stdout);
		}

		if (block) msleep(100);

	} while (p < total && block);

	if (block) printf(" ]\n");
}

struct function_tree * get_pending_subtree(struct workload *wl) {
	pthread_mutex_lock(&wl->mutex);

	int i;
	for (i = 0; i < wl->num; i++) {
		if (!wl->processed[i]) {
			wl->processed[i] = 1;

			pthread_mutex_unlock(&wl->mutex);

			return wl->subtree + i;
		}
	}

	pthread_mutex_unlock(&wl->mutex);

	return NULL;
}

void thread_pool_do(thread_pool_worker thread, struct thread_env *te) {
	struct workload wl;

	wl.num = ceildiv(te->bin->tree->num, WORKLOAD_NUM);

	wl.subtree = (struct function_tree *) malloc(wl.num * sizeof(struct function_tree));

	wl.processed = (int *) malloc(wl.num * sizeof(int));
	memset(wl.processed, 0, wl.num * sizeof(int));

	pthread_mutex_init(&wl.mutex, NULL);

	int i;
	for (i = 0; i < wl.num; i++) {
		wl.subtree[i].num = min(WORKLOAD_NUM, te->bin->tree->num - (i * WORKLOAD_NUM));
		wl.subtree[i].function = te->bin->tree->function + i * WORKLOAD_NUM;
	}

	te->workload = &wl;

	pthread_t tid[THREADS];

	for (i = 0; i < THREADS; i++) {
		pthread_create(tid + i, NULL, (void *(*)(void *)) thread, te);
	}

	int s = 0;
	progress_bar(wl.processed, wl.num, wl.num, &s, 1);

	for (i = 0; i < THREADS; i++) {
		pthread_join(tid[i], NULL);
	}

	te->workload = NULL;

	pthread_mutex_destroy(&wl.mutex);

	free(wl.processed);

	free(wl.subtree);
}

int is_rva_visited(rva *visited, int num, rva offset) {
	int i;
	for (i = 0; i < num; i++) {
		if (offset == visited[i]) return 1;
	}
	return 0;
}

int verify_function_size(pe_section_header *header, pe_buffer *section, rva func, int size) {
	if (is_aligned(func + size)) {
		return 1;
	} else {
		int off;
		bea_disasm_init(dasm);
		bea_disasm_one(dasm, off, section->data, header->virtual_size, (UIntPtr) section->data + func + size);

		return (dasm.Instruction.Opcode == INSTR_PAD);
	}

	error:

	return 0;
}

int _get_function_size(pe_file *pef, pe_section_header *header, pe_buffer *section, struct function *func, rva offset, rva **visited, int *num, int _cond) {
	bea_disasm_init(dasm);

	int rc = 1;

	int imm = 0;

	int cond = _cond;

	int off;
	for_each_instruction(dasm, off, section->data, header->virtual_size, offset) {
		rva eip_off = dasm.EIP - (UIntPtr) section->data;
		array_insert(*visited, *num, rva, eip_off);

		/* save immediates for our cheap switch struct walking code */
		if (dasm.Instruction.Immediat) imm = dasm.Instruction.Immediat;

		if (dasm.Instruction.BranchType == RetType) {
			rc &= 0;

			break;
		} else if (dasm.Instruction.BranchType && ((dasm.Instruction.BranchType <= JmpType) || (dasm.Instruction.BranchType > RetType))) {
			if (dasm.Instruction.BranchType != JmpType) {
				cond = 1;
			}

			if (dasm.Instruction.AddrValue) { /* jump target specified by given offset */
				/* in case of a 32 bit offset treat the instruction like a return / call */
				if (off == 5) {
					if (dasm.Instruction.BranchType == JmpType) {
						rc &= 0;

						break;
					} else {
						continue;
					}
				} else if (dasm.Instruction.BranchType == JmpType) { /* unconditional jump */
					if (pe_section_data_contains(section, header, dasm.Instruction.AddrValue)) {
						if (!is_rva_visited(*visited, *num, dasm.Instruction.AddrValue - (unsigned long) section->data)) {
							/* if the first instruction is jmp or there is no preceding conditional jump treat it like a return */
							if (*num == 1 || !cond) {
								rc &= 0;

								break;
							}

							/* there might be vaild subsequent jumps actually, only jumps without any preceeding conditional ones are suspicious */
							//cond = 0;

							dasm.EIP = dasm.Instruction.AddrValue - off;

							continue;
						} else {
							rc &= 0;

							break;
						}
					} else {
						break;
					}
				} else if (pe_section_data_contains(section, header, dasm.Instruction.AddrValue) && !is_rva_visited(*visited, *num, dasm.Instruction.AddrValue - (unsigned long) section->data)) { /* conditinal jump */
					rc &= _get_function_size(pef, header, section, func, dasm.Instruction.AddrValue - (unsigned long) section->data, visited, num, cond);
				}
			} else if ((HIWORD(dasm.Argument1.ArgType) == MEMORY_TYPE) && !dasm.Argument1.Memory.BaseRegister) { /* jump target stored in memory or addressed via registers */
				/* jump to offset stored in memory, unlikely to be within function boundaries; treat like a return */
				if (!dasm.Argument1.Memory.IndexRegister) {
					rc &= 0;

					break;
				} else if (FOLLOW_SWITCH) {
					UIntPtr index = imm;
					UIntPtr eip = (UIntPtr) section->data + (dasm.Argument1.Memory.Displacement + (dasm.Argument1.Memory.Scale * index) - pe_section_base(pef, header));

					if (dasm.Instruction.BranchType == JmpType) {
						if (pe_section_data_contains(section, header, eip)) {
							if (!is_rva_visited(*visited, *num, eip - (UIntPtr) section->data)) {
								if (*num == 1 || !cond) {
									rc &= 0;

									break;
								}

								/* see comment :193 */
								//cond = 0;

								dasm.EIP = eip - off;

								continue;
							} else  {
								rc &= 0;

								break;
							}
						} else {
							break;
						}
					} else if (pe_section_data_contains(section, header, eip) && !is_rva_visited(*visited, *num, eip - (UIntPtr) section->data)) {
						rc &= _get_function_size(pef, header, section, func, eip - (UIntPtr) section->data, visited, num, cond);
					}
				} else if (dasm.Instruction.BranchType == JmpType) { /* if we're not allowed to follow switch cases pretend we hit a return for unconditional jumps */
					rc &= 0;

					break;
				}
			} else if (dasm.Instruction.BranchType == JmpType) { /* we should never get here actually */
				break;
			}
		}
	}

	/* we found something return-ish, calculate size */
	if (!rc) {
		int size = dasm.EIP + off - (UIntPtr) (section->data + func->offset);

		if (size > 0 && func->size < size) {
			func->size = size;
		}
	}

	return rc;
}

int collapse_visited_offsets(struct function *func, rva *visited, int num) {
	int size = 0;

	int i;
	for (i = 0; i < num; i++) {
		if ((int) visited[i] - (int) func->offset > size) {
			size = visited[i] - func->offset;
		}
	}

	return size;
}

int get_function_size(pe_file *pef, pe_section_header *header, pe_buffer *section, struct function *func) {
	func->size = 0;

	rva *visited;
	int num;
	array_init(visited, num);

	/* disregarding our metric that checks for conditional jumps before taking an unconditional jump yields better results */
	int rc = _get_function_size(pef, header, section, func, func->offset, &visited, &num, 1);

	if (!rc) {
		int size = collapse_visited_offsets(func, visited, num); /* doesn't help - nevermind, it does! */
		
		if (size > func->size) {
			func->size = size;
		}
	}

	/*
	 * instead of deciding which jumps to treat as returns we could compare the calculated function size
	 * to the number of visited instructions resp. bytes; if we detect a huge descrepancy we iterate
	 * through the visited offsets backwards and re-calculate the function's size until the difference
	 * between the visited bytes and the function size is below our requirement
	 */

	array_destroy(visited, num);

	return rc;
}

int get_next_aligned_return(pe_file *pef, pe_section_header *header, pe_buffer *section, struct function *func) {
	bea_disasm_init(dasm);

	int off;
	for_each_opcode(dasm, off, section->data, header->virtual_size, func->offset) {
		if (off == UNKNOWN_OPCODE) {
			off = 1;
			continue;
		}

		if (dasm.Instruction.BranchType == RetType) {
			if (pe_section_data_contains(section, header, dasm.EIP + off)) {
				int size = dasm.EIP + off - ((UIntPtr) section->data + func->offset);
				if (verify_function_size(header, section, func->offset, size)) {
					func->size = size;
					return 0;
				}
			} else {
				return 0;
			}
		}
	}

	return 1;
}

int skip_pad_instructions(pe_section_header *header, pe_buffer *section, rva offset) {
	bea_disasm_init(dasm);

	int skip = 0;

	int off;
	for_each_instruction(dasm, off, section->data, header->virtual_size, offset) {
		if (dasm.Instruction.Opcode == INSTR_PAD) {
			skip++;
		} else {
			break;
		}
	}

	return skip;
}

/*
#include "ida.h"

void ida_statistics(pe_file *pef, pe_section_header *header, struct function_tree *tree) {
	printf("\nIDA Pro statistics:\n");

	int last = 0;

	int m = 0;
	int sm = 0;
	int sl = 0;
	int sg = 0;
	int sne = 0;
	int total = 0;
	int itotal = 0;
	int h = 0;
	int i;
	for (i = 0; i < sizeof(ida) / sizeof(struct ida_function); i++) {
		int j;
		for (j = last; j < tree->num; j++) {
			if (tree->function[j].offset == ida_offset(pef, header, ida[i])) {
				m++;
				if (tree->function[j].size == ida[i].size) {
					sm++;
				} else if (tree->function[j].size < ida[i].size) {
					sl++;
					sne++;
					total += abs((int) tree->function[j].size - (int) ida[i].size);
				} else {
					sg++;
					sne++;
					total += abs((int) tree->function[j].size - (int) ida[i].size);
				}

				//last = ++j;

				break;
			}
		}
		itotal += ida[i].size;

		if (ida[i].size > 1000) h++;
	}

	printf("matched %f %% functions (%i/%i)\n", (double) m * 100 / (double) (sizeof(ida) / sizeof(struct ida_function)), m, sizeof(ida) / sizeof(struct ida_function));
	printf("matching functions match in size: %f %% (%i/%i)\n", (double) sm * 100 / (sizeof(ida) / sizeof(struct ida_function)), sm, (sizeof(ida) / sizeof(struct ida_function)));
	if (sne) printf("functions not matching in size %f %% less than / %f %% greater than IDA function in size\n", (double) sl * 100 / (double) sne, (double) sg * 100 / (double) sne);
	if (sne) printf("function size discrepancy (average): %i\n", total / sne);
	printf("average IDA function size: %i\n", itotal / (sizeof(ida) / sizeof(struct ida_function)));
	printf("huge IDA functions: %i\n", h);
	printf("\n");
}
*/

int check_duplicates(struct function_tree *tree) {
	int dup = 0;
	int i;
	for (i = 0; i < tree->num; i++) {
		int j;
		for (j = 0; j < tree->num; j++) {
			if (i != j && tree->function[i].offset == tree->function[j].offset) dup++;
		}
	}
	return dup;
}

int retrieve_rva_from_data_section(pe_file *pef, pe_section_header *header, pe_buffer *section, va disp, rva *offset) {
	pe_buffer *s = pe_file_get_section_data_by_va(pef, disp);
	pe_section_header *h = pe_file_get_section_header_by_va(pef, disp);

	if (s && h) {
		rva index = (rva) disp - pe_section_base(pef, h);
		/* not entirely sure if this will work on 64 bit */
		va addr = (va) _va(pef, &s->data[index]);

		if (pe_section_contains(pef, header, addr)) {
			UIntPtr eip = (UIntPtr) (section->data + (addr - pe_section_base(pef, header)));

			if (pe_section_data_contains(section, header, eip)) {
				*offset = (rva) (eip - (unsigned long) section->data);

				return 0;
			}
		}
	}

	return 1;
}

void * build_call_site(struct thread_env *env) {
	int *n = get_thread_arg(env, 0, int *);
	int *t = get_thread_arg(env, 1, int *);
	//int *m = ((int **)env->arg)[2];	
	
	pthread_mutex_t *stats_m = get_thread_arg(env, 3, pthread_mutex_t *);
	
	pe_file *pef = env->bin->pef;
	pe_section_header *header = env->bin->header;
	pe_buffer *section = env->bin->section;
	struct function_tree *tree;

	bea_disasm_init(dasm);

	while ((tree = get_pending_subtree(env->workload))) {
		int i;
		for (i = 0; i < tree->num; i++) {
			array_init(tree->function[i].call_site.callee, tree->function[i].call_site.num);

			int off;
			for_each_instruction(dasm, off, section->data, tree->function[i].offset + tree->function[i].size, tree->function[i].offset) {
				if (dasm.Instruction.BranchType == CallType) {
					pthread_mutex_lock(stats_m);
					(*t)++;
					pthread_mutex_unlock(stats_m);

					rva callee;

					if (dasm.Instruction.AddrValue && pe_section_data_contains(section, header, dasm.Instruction.AddrValue)) {
						callee = dasm.Instruction.AddrValue - (unsigned long) section->data;
					} else if (HIWORD(dasm.Argument1.ArgType) == MEMORY_TYPE) {
						if (!(dasm.Argument1.Memory.BaseRegister || dasm.Argument1.Memory.IndexRegister || dasm.Argument1.Memory.Scale)) {
							/* these retrieved address seem off; I doubt this actually works with static analysis, so we'll skip it for now */
							continue;
							if (retrieve_rva_from_data_section(pef, header, section, (va) dasm.Argument1.Memory.Displacement, &callee)) {
								continue;
							}
						} else { /* using base + index * scale */
							/* we might be able to our immediate trick, although there are no calls that don't use a base register */
							continue;
						}
					} else { /* register argument */
						continue;
					}

					array_insert(tree->function[i].call_site.callee, tree->function[i].call_site.num, rva, callee);
				}
			}

			pthread_mutex_lock(stats_m);
			*n += tree->function[i].call_site.num;
			pthread_mutex_unlock(stats_m);

			/*int j;
			for (j = 0; j < tree->function[i].call_site.num; j++) {
				int k;
				for (k = 0; k < tree->num; k++) {
					if (tree->function[i].call_site.callee[j] == tree->function[k].offset) {
						(*m)++;
					}
				}
			}*/
		}
	}

	pthread_exit(NULL);
}

int reference_call_site(pe_file *pef, pe_section_header *header, pe_buffer *section, struct function_tree *tree) {
	int m = 0;
	int a = 0;
	int u = 0;
	int am = 0;
	int n = 0;

	int i, j, k;

	goto known;

	bea_disasm_init(dasm);
	int t = 0;
	for (i = 0; i < tree->num; i++) {

		int off;
		for_each_instruction(dasm, off, section->data, tree->function[i].offset + tree->function[i].size, tree->function[i].offset) {
			if (dasm.Instruction.BranchType == CallType) {
				t++;

				rva callee;

				if (dasm.Instruction.AddrValue && pe_section_data_contains(section, header, dasm.Instruction.AddrValue)) {
					callee = dasm.Instruction.AddrValue - (unsigned long) section->data;
				} else if (HIWORD(dasm.Argument1.ArgType) == MEMORY_TYPE) {
					if (!(dasm.Argument1.Memory.BaseRegister || dasm.Argument1.Memory.IndexRegister || dasm.Argument1.Memory.Scale)) {
						/* these retrieved address seem off; I doubt this actually works with static analysis, so we'll skip it for now */
						continue;
						if (retrieve_rva_from_data_section(pef, header, section, (va) dasm.Argument1.Memory.Displacement, &callee)) {
							continue;
						}
					} else { /* using base + index * scale */
						/* we might be able to our immediate trick, although there are no calls that don't use a base register */
						continue;
					}
				} else { /* register argument */
					continue;
				}

				n++;
			}
		}
	}

	printf("successfully resolved calls: %f %%\n", percent(n, t));
	printf("resolved %i calls\n", n);

	known:

	for (i = 0; i < tree->num; i++) {
		int match = 0;
		for (j = 0; j < tree->function[i].call_site.num; j++) {
			for (k = 0; k < tree->num; k++) {
				if (tree->function[i].call_site.callee[j] == tree->function[k].offset) {
					m++;
					match = 1;
					break;
				}
			}

			if (is_aligned(tree->function[i].call_site.callee[j])) {
				a++;
				if (match) am++;
				else u++;
			}

			n++;
		}
	}

	printf("known callees: %f %% (%i/%i)\n", percent(m, n), m, n);
	printf("aligned (total): %f %% (%i)\n", percent(a, n), a);
	printf("aligned (unknown): %f %% (%i)\n", percent(u, n - m), u);
	printf("aligned (known): %f %% (%i)\n", percent(am, m), am);

	return n;
}

int fix_function_sizes(pe_file *pef, pe_section_header *header, pe_buffer *section, struct function_tree *tree) {
	int n = 0;

	bea_disasm_init(dasm);

	int s = 0;
	printf("progress: [ ");
	fflush(stdout);

	int i;
	for (i = 0; i < tree->num; i++) {

		int off;
		for_each_instruction(dasm, off, section->data, tree->function[i].offset + tree->function[i].size, tree->function[i].offset) {
			if (dasm.Instruction.Opcode == INSTR_PAD) {
				int skip = skip_pad_instructions(header, section, dasm.EIP - (unsigned long) section->data);

				rva offset = dasm.EIP + skip - (unsigned long) section->data;

				size_t new = offset - tree->function[i].offset - skip;

				if (is_aligned(offset)) {
					struct function func = { .offset = offset, .size = tree->function[i].size - new - skip };
					tree->function[i].size = new;
					array_insert(tree->function, tree->num, struct function, func);
					n++;

					break;
				}

				off = max(off, skip); /* we hit a pad instruction so we skip anyway */
			}
		}

		progress_bar(&i, 1, tree->num, &s, 0);
	}

	printf(" ]\n");

	return n;
}

int fix_call_sites(pe_file *pef, pe_section_header *header, pe_buffer *section, struct function_tree *tree) {
	int n = 0;

	bea_disasm_init(dasm);

	int s = 0;
	printf("progress: [ ");
	fflush(stdout);

	int i;
	for (i = 0; i < tree->num; i++) {
		int j;
		for (j = 0; j < tree->function[i].call_site.num; j++) {
			int known = 0;
			struct function *func = NULL;

			//if (!is_aligned(tree->function[i].call_site.callee[j])) continue;

			int k;
			for (k = 0; k < tree->num; k++) {
				if (tree->function[k].offset == tree->function[i].call_site.callee[j]) {
					known = 1;
					break;
				} else if (tree->function[i].call_site.callee[j] > tree->function[k].offset && tree->function[i].call_site.callee[j] < tree->function[k].offset + tree->function[k].size) {
					func = tree->function + k;
					break;
				}
			}

			if (!known && func) {
				struct function _new = { .offset = tree->function[i].call_site.callee[j] };
				_new.size = func->offset + func->size - _new.offset;
				func->size = func->size - _new.size;
				array_insert(tree->function, tree->num, struct function, _new);
				struct function *new = tree->function + tree->num - 1;
				n++;

				/* fix up corresponding call sites */
				array_destroy(func->call_site.callee, func->call_site.num);
				array_init(func->call_site.callee, func->call_site.num);
				array_init(new->call_site.callee, new->call_site.num);

				int off;
				for_each_instruction(dasm, off, section->data, func->offset + func->size, func->offset) {
					if (dasm.Instruction.BranchType == CallType) {
						rva callee;

						if (dasm.Instruction.AddrValue && pe_section_data_contains(section, header, dasm.Instruction.AddrValue)) {
							callee = dasm.Instruction.AddrValue - (unsigned long) section->data;
						} else if (HIWORD(dasm.Argument1.ArgType) == MEMORY_TYPE) {
							if (!(dasm.Argument1.Memory.BaseRegister || dasm.Argument1.Memory.IndexRegister || dasm.Argument1.Memory.Scale)) {
								/* these retrieved address seem off; I doubt this actually works with static analysis, so we'll skip it for now */
								continue;
								if (retrieve_rva_from_data_section(pef, header, section, (va) dasm.Argument1.Memory.Displacement, &callee)) {
									continue;
								}
							} else { /* using base + index * scale */
								/* we might be able to our immediate trick, although there are no calls that don't use a base register */
								continue;
							}
						} else { /* register argument */
							continue;
						}

						array_insert(func->call_site.callee, func->call_site.num, rva, callee);
					}
				}

				for_each_instruction(dasm, off, section->data, new->offset + new->size, new->offset) {
					if (dasm.Instruction.BranchType == CallType) {
						rva callee;

						if (dasm.Instruction.AddrValue && pe_section_data_contains(section, header, dasm.Instruction.AddrValue)) {
							callee = dasm.Instruction.AddrValue - (unsigned long) section->data;
						} else if (HIWORD(dasm.Argument1.ArgType) == MEMORY_TYPE) {
							if (!(dasm.Argument1.Memory.BaseRegister || dasm.Argument1.Memory.IndexRegister || dasm.Argument1.Memory.Scale)) {
								/* these retrieved address seem off; I doubt this actually works with static analysis, so we'll skip it for now */
								continue;
								if (retrieve_rva_from_data_section(pef, header, section, (va) dasm.Argument1.Memory.Displacement, &callee)) {
									continue;
								}
							} else { /* using base + index * scale */
								/* we might be able to our immediate trick, although there are no calls that don't use a base register */
								continue;
							}
						} else { /* register argument */
							continue;
						}

						array_insert(new->call_site.callee, new->call_site.num, rva, callee);
					}
				}
			}
		}

		progress_bar(&i, 1, tree->num, &s, 0);
	}

	printf(" ]\n");

	return n;
}

int build_function_tree(pe_file *pef, pe_section_header *header, pe_buffer *section, struct function_tree *tree) {
	printf("starting function analysis\n");

	array_init(tree->function, tree->num);

	struct function func = { .call_site.callee = NULL };

	int skip;

	int f = 0, s = 0, u = 0, l = 0;

	printf("progress: [ ");
	fflush(stdout);

	int i = 0;
	while (i < header->virtual_size) {
		func.offset = i;

		if (get_function_size(pef, header, section, &func)) {
			f++;

			if (get_next_aligned_return(pef, header, section, &func)) {
				break;
			}
		}

		//printf("extracted function sub_%08lX: %lX - %lX\n", (unsigned long) pe_section_base(pef, header) + func.offset, (unsigned long) func.offset, (unsigned long) func.offset + func.size - 1);

		array_insert(tree->function, tree->num, struct function, func);

		if (!is_aligned(func.offset)) u++;

		l += func.size;

		skip = skip_pad_instructions(header, section, i + func.size);

		i += func.size + skip;

		progress_bar(&i, 1, header->virtual_size, &s, 0);
	}
	
	if (i >= header->virtual_size) {
		printf(" ]\n");
	} else {
		printf("\n");
	}

	if (i < header->virtual_size) {
		printf("failed to calculate size of function sub_%08lX\n", (unsigned long) pe_section_base(pef, header) + func.offset);
		printf("aborting funtion analysis\n");
	} else {
		printf("function analysis succeded\n");
	}

	if (f) printf("resorted to simply checking for aligned return instruction %i time(s)\n", f);

	if (u) printf("%.2f%% functions are not aligned\n", percent(u, tree->num));

	printf("average function size: %i bytes\n", l / tree->num);

	printf("re-evaluating function sizes\n");
	f = fix_function_sizes(pef, header, section, tree);
	if (f) printf("split %i functions\n", f);

	printf("extracting call site for extracted functions...\n");

	int n = 0, t = 0, m = 0;

	pthread_mutex_t stats_m;

	void *arg[] = { &n, &t, &m, &stats_m };

	struct binary bin = { pef, header, section, tree };

	struct thread_env env = { .bin = &bin, .arg = arg };

	pthread_mutex_init(&stats_m, NULL);

	printf("starting call site analysis\n");

	thread_pool_do(build_call_site, &env);

	printf("call site analysis succeded\n");
	printf("successfully resolved calls: %.2f%% (%i)\n", percent(n, t), n);

	pthread_mutex_destroy(&stats_m);

	if (FIX_CALL_SITE) {
		printf("re-evaluating call sites...\n");
		f = fix_call_sites(pef, header, section, tree);
		if (f) printf("isolated %i callees\n", f);
	}

	//reference_call_site(pef, header, section, tree);

	//ida_statistics(pef, header, tree);

	//printf("duplicates: %i\n", check_duplicates(tree));	

	return tree->num;
}

int metric_function_size(struct binary *ref, struct function *f, struct binary *bin, struct function *g, double *m) {
	if ((double) abs((int) f->size - (int) g->size) / max(f->size, g->size) > MAX_SIZE_DIFF) {
		return 1;
	}

	if (f->size > g->size) {
		*m = (double) g->size / (double) f->size;
		return 0;
	} else {
		*m = (double) f->size / (double) g->size;
		return 0;
	}
}

int instrcmp(DISASM *a, DISASM *b) {
	int i_m = 1;

	/* compare opcodes */
	//i_m &= (a->Instruction.Opcode == b->Instruction.Opcode); /* we ignore prefixes for now */
	//i_m &= (LOWORD(a->Instruction.Category) == LOWORD(b->Instruction.Category));
	i_m &= !strcmp(a->Instruction.Mnemonic, b->Instruction.Mnemonic);

	/* compare arguments */
	i_m &= (HIWORD(a->Argument1.ArgType) == HIWORD(b->Argument1.ArgType));
	i_m &= (HIWORD(a->Argument2.ArgType) == HIWORD(b->Argument2.ArgType));
	i_m &= (HIWORD(a->Argument3.ArgType) == HIWORD(b->Argument3.ArgType));

	/* compare used immediates */
	i_m &= (a->Instruction.Immediat == b->Instruction.Immediat);

	/* compare memory access, disregarding displacement */
	/*if (i_m && ((a->Argument1.ArgType & 0xFFFF0000) == MEMORY_TYPE)) {
		i_m &= (a->Argument1.Memory.BaseRegister == b->Argument1.Memory.BaseRegister);
		i_m &= (a->Argument1.Memory.IndexRegister == b->Argument1.Memory.IndexRegister);
		i_m &= (a->Argument1.Memory.Scale == b->Argument1.Memory.Scale);
		//i_m &= (a->Argument1.Memory.Displacement == b->Argument1.Memory.Displacement);
	}
	if (i_m && ((a->Argument2.ArgType & 0xFFFF0000) == MEMORY_TYPE)) {
		i_m &= (a->Argument2.Memory.BaseRegister == b->Argument2.Memory.BaseRegister);
		i_m &= (a->Argument2.Memory.IndexRegister == b->Argument2.Memory.IndexRegister);
		i_m &= (a->Argument2.Memory.Scale == b->Argument2.Memory.Scale);
		//i_m &= (a->Argument2.Memory.Displacement == b->Argument2.Memory.Displacement);
	}
	if (i_m && ((a->Argument3.ArgType & 0xFFFF0000) == MEMORY_TYPE)) {
		i_m &= (a->Argument3.Memory.BaseRegister == b->Argument3.Memory.BaseRegister);
		i_m &= (a->Argument3.Memory.IndexRegister == b->Argument3.Memory.IndexRegister);
		i_m &= (a->Argument3.Memory.Scale == b->Argument3.Memory.Scale);
		//i_m &= (a->Argument3.Memory.Displacement == b->Argument3.Memory.Displacement);
	}*/

	return !i_m;
}

int metric_first_instruction(struct binary *ref, struct function *f, struct binary *bin, struct function *g, double *m) {
	bea_disasm_init(rdasm);
	bea_disasm_init(bdasm);

	int roff, boff;
	bea_disasm_one(rdasm, roff, ref->section->data, ref->header->virtual_size, (UIntPtr) ref->section->data + f->offset + f->size);
	bea_disasm_one(bdasm, boff, bin->section->data, bin->header->virtual_size, (UIntPtr) bin->section->data + g->offset + g->size);

	int rc = instrcmp(&rdasm, &bdasm);

	if (!rc) {
		*m = 1.0;
	}

	return rc;

	error:

	return 1;
}

int disassemble_function(pe_file *pef, pe_section_header *header, pe_buffer *section, struct function *func, DISASM **d, int *n) {
	array_init(*d, *n);

	bea_disasm_init(dasm);

	int off;
	for_each_instruction(dasm, off, section->data, func->offset + func->size, func->offset) {
		array_insert(*d, *n, DISASM, dasm);
	}

	return *n;
}

int get_next_match(DISASM *r, int i, int nr, DISASM *b, int j, int nb) {
	if (i >= nr) return nb;
	
	int k;
	for (k = j; k < nb; k++) {
		if (!instrcmp(r + i, b + k)) {
			return k;
		}
	}

	return k;
}

int get_matching_instructions(DISASM *r, int *mr, int nr, DISASM *b, int *mb, int nb) {
	int m = 0;

	int i, j, k;
	for (i = 0, j = 0; i < nr; i++) {
		int match = 0;

		for (k = j; k < nb; k++) {
			if (!instrcmp(r + i, b + k)) {
				if (get_next_match(r, i + 1, nr, b, j, nb) >= k) {
					match = 1;
					j = k;
					break;
				}
			}
		}

		if (match) {
			mr[i] = 1;
			mb[j] = 1;
			j++;
			m++;
		}
	}

	return m;
}

int metric_assembly(struct binary *ref, struct function *f, struct binary *bin, struct function *g, double *m) {
	DISASM *r, *b;
	int nr, nb;

	if (!disassemble_function(ref->pef, ref->header, ref->section, f, &r, &nr)) {
		return 1;
	}
	if (!disassemble_function(bin->pef, bin->header, bin->section, g, &b, &nb)) {
		array_destroy(r, nr);
		return 1;
	}

	int *mr = (int *) calloc(nr, sizeof(int));
	int *mb = (int *) calloc(nb, sizeof(int));

	int nm = get_matching_instructions(r, mr, nr, b, mb, nb);

	*m = (double) nm / (double) nr;

	array_destroy(r, nr);
	array_destroy(b, nb);

	free(mr);
	free(mb);

	return 0;
}

int get_calling_functions(struct binary *bin, struct function *callee, struct function_tree *caller, size_t min) {
	array_init(caller->function, caller->num);

	int i;
	for (i = 0; i < bin->tree->num; i++) {
		int j;
		for (j = 0; j < bin->tree->function[i].call_site.num; j++) {
			if (bin->tree->function[i].call_site.callee[j] == callee->offset) {
				if (!min || bin->tree->function[i].size >= min) {
					array_insert(caller->function, caller->num, struct function, bin->tree->function[i]);
				}
			}
		}
	}

	return caller->num;
}

int metric_caller(struct binary *ref, struct function *f, struct binary *bin, struct function *g, double *m) {
	struct function_tree ref_caller;
	struct function_tree bin_caller;

	get_calling_functions(ref, f, &ref_caller, MIN_CALLER_SIZE);
	get_calling_functions(bin, g, &bin_caller, MIN_CALLER_SIZE);

	if ((double) abs(ref_caller.num - bin_caller.num) / (double) max(ref_caller.num, bin_caller.num) > MAX_CALLER_NUM_DIFF / min(1.0, (double) ref_caller.num / (double) CALLER_NUM_SENSITIVITY)) {
		array_destroy(ref_caller.function, ref_caller.num);
		array_destroy(bin_caller.function, bin_caller.num);
		
		return 1;
	}

	int matched[bin_caller.num];
	memset(matched, 0, bin_caller.num * sizeof(int));

	*m = 0;

	int i;
	for (i = 0; i < ref_caller.num; i++) {
		double _m = 0, __m;
		int k = -1;

		int j;
		for (j = 0; j < bin_caller.num; j++) {
			if (matched[j]) {
				continue;
			}

			if (!metric_assembly(ref, ref_caller.function + i, bin, bin_caller.function + j, &__m)) {
				if (_m < __m) {
					_m = __m;
					k = j;
				}
			}
		}

		if (k >= 0) {
			matched[k] = 1;
		}

		*m += _m;
	}

	if (!ref_caller.num) {
		*m = 1.0;
	} else {
		*m /= ref_caller.num;
	}

	array_destroy(ref_caller.function, ref_caller.num);
	array_destroy(bin_caller.function, bin_caller.num);

	return 0;
}

int metric_callee(struct binary *ref, struct function *f, struct binary *bin, struct function *g, double *m) {
	if (!f->call_site.num) {
		*m = 1.0;
		return 0;
	}

	if ((double) abs(f->call_site.num - g->call_site.num) / (double) max(f->call_site.num, g->call_site.num) > MAX_CALLEE_NUM_DIFF) {
		return 1;
	}

	int matched[f->call_site.num];
	memset(matched, 0, f->call_site.num * sizeof(int));

	*m = 0;

	int t = 0;

	int i;
	for (i = 0; i < f->call_site.num; i++) {
		double _m = 0, __m;
		int k = -1;

		struct function *u = get_function(ref->tree, f->call_site.callee[i]);

		if (!u) continue;

		t++;

		int j;
		for (j = 0; j < g->call_site.num; j++) {
			if (matched[j]) {
				continue;
			}

			struct function *v = get_function(bin->tree, g->call_site.callee[j]);

			if (!v) continue;

			if (!metric_assembly(ref, u, bin, v, &__m)) {
				if (_m < __m) {
					_m = __m;
					k = j;
				}
			}
		}

		if (k >= 0) {
			matched[k] = 1;
		}

		*m += _m;
	}

	if (t) {
		*m /= t;
	} else {
		*m = 1.0;
	}

	return 0;
}

void * find_matching_function(struct thread_env *env) {
	struct match *match = get_thread_arg(env, 0, struct match *);
	struct metric *metric = get_thread_arg(env, 1, struct metric *);
	struct function_tree *tree;

	while ((tree = get_pending_subtree(env->workload))) {
		int i;
		for (i = 0; i < tree->num; i++) {
			double m = 1.0, __m;
			double _m[metric->num];

			int j;
			for (j = 0; j < metric->num; j++) {
				if (metric->apply[j](env->ref.bin, env->ref.function, env->bin, tree->function + i, &__m)) {
					break;
				} else {
					m *= __m;
					_m[j] = __m;
				}
			}

			if (j < metric->num) continue;

			pthread_mutex_lock(&match->mutex);

			int k;
			for (k = 0; k < match->num; k++) {
				if (k >= match->n || m > match->top[k].quality.total) {
					void *copy;
					int n = min(match->n - k, match->num - k - 1);

					if (n == match->num) { /* an entry gets evicted; free its memory */
						free(match->top[match->num - 1].quality.metric);
					}

					if (n > 0) {
						copy = malloc(n * sizeof(*match->top));
						memcpy(copy, match->top + k, n * sizeof(*match->top));
					}

					match->top[k].function = tree->function + i;
					match->top[k].quality.total = m;
					match->top[k].quality.metric = (double *) malloc(metric->num * sizeof(double));
					memcpy(match->top[k].quality.metric, _m, metric->num * sizeof(double));

					if (n > 0) {
						memcpy(match->top + k + 1, copy, n * sizeof(*match->top));
						free(copy);
					}

					match->n = min(match->n + 1, match->num);

					break;
				}
			}

			pthread_mutex_unlock(&match->mutex);
		}
	}

	pthread_exit(NULL);
}

int update_function_offset(struct binary *ref, struct binary *bin, struct function *func, struct match *match, struct metric *metric) {
	void *arg[] = { match, metric };

	struct thread_env env = { .bin = bin, .ref.bin = ref, .ref.function = func, .arg = arg };

	pthread_mutex_init(&match->mutex, NULL);

	match->top = malloc(match->num * sizeof(*match->top));
	match->metric = metric;
	match->n = 0;

	thread_pool_do(find_matching_function, &env);

	pthread_mutex_destroy(&match->mutex);

	return match->n;
}

int get_max_line_length(DISASM *d, int n) {
	int len = 0;

	int i;
	for (i = 0; i < n; i++) {
		int l = strlen(d[i].CompleteInstr);

		if (l && (l + 1) > len) {
			len = l + 1;
		}
	}

	return len;
}

void dump_assembly_match(struct binary *ref, struct function *f, struct binary *bin, struct function *g) {
	DISASM *r, *b;
	int nr, nb;

	if (!disassemble_function(ref->pef, ref->header, ref->section, f, &r, &nr)) {
		return;
	}
	if (!disassemble_function(bin->pef, bin->header, bin->section, g, &b, &nb)) {
		array_destroy(r, nr);
		return;
	}

	int len = get_max_line_length(r, nr);
	if (!len) {
		array_destroy(r, nr);
		array_destroy(b, nb);

		return;
	}

	char blank[len];
	memset(blank, ' ', len);
	blank[len - 1] = '\0';

	int *mr = (int *) calloc(nr, sizeof(int));
	int *mb = (int *) calloc(nb, sizeof(int));

	get_matching_instructions(r, mr, nr, b, mb, nb);

	char *s = strdup(blank);

	get_function_name(ref->pef, ref->header, f, s);
	printf("%s --- ", s);

	get_function_name(bin->pef, bin->header, g, s);
	printf("%s\n", s);

	free(s);

	int i, j;
	for (i = 0, j = 0; i < nr; i++) {
		if (!mr[i]) {
			s = strdup(blank);
			memcpy(s, r[i].CompleteInstr, strlen(r[i].CompleteInstr));
			printf("%s --- \n", s);
			free(s);
		} else {
			while (!mb[j]) {
				printf("%s --- %s\n", blank, b[j].CompleteInstr);
				j++;
			}
			s = strdup(blank);
			memcpy(s, r[i].CompleteInstr, strlen(r[i].CompleteInstr));
			printf("%s --- %s\n", s, b[j].CompleteInstr);
			free(s);
			j++;
		}
	}

	free(mr);
	free(mb);

	array_destroy(r, nr);
	array_destroy(b, nb);
}

int main(int argc, char **argv) {
	if (argc < 3) {
		printf("usage: binupdate <file> <file>\n");
		exit(EXIT_FAILURE);
	}

	printf("looading beaengine... ");
	void *h = dlopen("../beaengine/libBeaEngine_d.so", RTLD_LAZY);
	if (!h) {
		printf("failed to load beaengine\n");
		exit(EXIT_FAILURE);
	}
	printf("done\n");
	printf("resolving symbol Disasm... ");
	bea_disasm = dlsym(h, "Disasm");
	if (!bea_disasm) {
		printf("failed to resolve Disasm\n");
		exit(EXIT_FAILURE);
	}
	printf("done\n\n");

	pe_file ref_pef, new_pef;

	printf("loading reference PE file %s\n", argv[1]);
	if (!pe_file_load(argv[1], &ref_pef)) {
		printf("failed to load %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}
	printf("done\n\n");

	printf("loading updated PE file %s\n", argv[2]);
	if (!pe_file_load(argv[2], &new_pef)) {
		printf("failed to load %s\n", argv[2]);
		exit(EXIT_FAILURE);
	}
	printf("done\n\n");

	pe_buffer *ref_code = pe_file_get_section_data(&ref_pef, ".text");
	pe_section_header *ref_header = pe_file_get_section_header(&ref_pef, ".text");

	pe_buffer *new_code = pe_file_get_section_data(&new_pef, ".text");
	pe_section_header *new_header = pe_file_get_section_header(&new_pef, ".text");

	if (!ref_code || !ref_header || !new_code || !new_header) {
		printf("failed to retrieve section data (.text)\n");
		exit(EXIT_FAILURE);
	}

	int n;
	printf("building function tree of reference file...\n");
	struct function_tree ref_tree;
	n = build_function_tree(&ref_pef, ref_header, ref_code, &ref_tree);
	printf("successfully built function tree\n");
	printf("extracted %i functions\n\n", n);

	printf("building function tree of updated file...\n");
	struct function_tree new_tree;
	n = build_function_tree(&new_pef, new_header, new_code, &new_tree);
	printf("successfuly built function tree\n");
	printf("extracted %i functions\n", n);

	struct binary ref = { &ref_pef, ref_header, ref_code, &ref_tree };
	struct binary new = { &new_pef, new_header, new_code, &new_tree };

	struct metric metric;
	metric_init(metric);
	metric_add(&metric, metric_first_instruction, "first instruction");
	metric_add(&metric, metric_function_size, "function size");
	metric_add(&metric, metric_assembly, "assembly");
	metric_add(&metric, metric_caller, "caller");
	metric_add(&metric, metric_callee, "callee");
	
	//rva func = 0xe1a90;
	//rva func = 0xe1a30;
	//rva func = 0x149530;
	//rva func = 0x13eca0;
	//rva func = 0x141670;
	//rva func = 0x1810e0;
	va func;
	int top;

	while (fscanf(stdin, "%lx %i", (unsigned long *) &func, &top) == 2) {
		printf("\n");
		printf("updating offsets of function sub_%08lX (top %i)\n", (unsigned long) func, top);

		rva off = func - pe_section_base(&ref_pef, ref_header);
		struct function *f = get_function(&ref_tree, off);

		if (!f) {
			printf("error: sub_%08lX does not exist in function tree\n", (unsigned long) func);
			continue;
		}

		printf("reference function is %i bytes in size\n", f->size);

		struct match match;
		match_init(match, top);

		printf("analysing function tree...\n");
		n = update_function_offset(&ref, &new, f, &match, &metric);
		printf("found %i matching functions\n", n);

		int i;
		for (i = 0; i < n; i++) {
			printf("\n################################################################\n");

			char name[24] = { 0 };
			get_function_name(new.pef, new.header, match.top[i].function, name);

			printf("[%i] %s (%i bytes): %08X - %08X\n", i + 1, name, match.top[i].function->size, match.top[i].function->offset, match.top[i].function->offset + match.top[i].function->size);
			printf("total match quality: %f%%\n", match.top[i].quality.total * 100);
			
			int j;
			for (j = 0; j < metric.num; j++) {
				printf("metric %s: %f%%\n", match.metric->name[j], match.top[i].quality.metric[j] * 100);
			}
			printf("\n");

			dump_assembly_match(&ref, f, &new, match.top[i].function);
		}

		match_destroy(&match);
	}

	printf("\n");

	metric_destroy(metric);

	printf("unloading PE file %s\n\n", argv[1]);
	function_tree_destroy(&ref_tree);
	pe_file_free(&ref_pef);

	printf("unloading PE file %s\n\n", argv[2]);
	function_tree_destroy(&new_tree);
	pe_file_free(&new_pef);

	printf("unloading beaengine... ");
	dlclose(h);
	printf("done\n\n");

	printf("goodbye.\n");

	exit(EXIT_SUCCESS);
};
