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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pe.h"

#define abort(f) if ((f)) goto abort

pe_buffer pe_buffer_new(size_t size) {
	pe_buffer peb;
	peb.size = (peb.data = (unsigned char *) malloc(size * sizeof(unsigned char))) ? size : 0;

	return peb;
}

void pe_buffer_free(pe_buffer peb) {
	if (peb.data) free(peb.data);
	peb.size = 0;
	peb.data = NULL;
}

void pe_file_free(pe_file *pef) {
	pe_buffer_free(pef->header.msdos_stub);

	if (pef->section_table) free(pef->section_table);

	pe_buffer_free(pef->string_table);

	if (pef->section) {
		int i;
		for (i = 0; i < pef->header.coff.number_of_sections; i++) {
			if (pef->section[i].name) free(pef->section[i].name);
			pe_buffer_free(pef->section[i].container);
		}

		free(pef->section);
	}
}

#define min(x, y) ((x) < (y) ? (x) : (y))

pe_file * pe_file_load(const char *file, pe_file *pef) {
	FILE *f = fopen(file, "rb");
	abort( !f );

	memset(pef, 0, sizeof(pe_file));

	/* retrieve file offset to PE signature */
	uint32_t sig_offset;
	abort( fseek(f, PE_MSDOS_STUB_SIGNATURE_OFFSET, SEEK_SET) );
	abort( fread(&sig_offset, sizeof(uint32_t), 1, f) != 1 );

	/* load msdos stub into structure */
	printf("loading MSDOS stub\n");
	pef->header.msdos_stub = pe_buffer_new(sig_offset);
	abort( !pef->header.msdos_stub.data );
	rewind(f);
	abort( fread(pef->header.msdos_stub.data, pef->header.msdos_stub.size, 1, f) != 1 );

	/* load PE signature into structure */
	printf("checking for PE signature\n");
	abort( fseek(f, sig_offset, SEEK_SET) );
	abort( fread(pef->header.signature, sizeof(pef->header.signature), 1, f) != 1 );
	abort( strncmp((char *) pef->header.signature, PE_IMAGE_FILE_SIGNATURE, sizeof(pef->header.signature)) );

	/* load coff header */
	printf("loading COFF header\n");
	abort(fread(&pef->header.coff, sizeof(pef->header.coff), 1, f) != 1 );

	/* load optional header */
	printf("loading optional header\n");
	abort( fread(&pef->header.optional.magic, sizeof(pef->header.optional.magic), 1, f) != 1 );
	if (pef->header.optional.magic == PE_IMAGE_FILE_STATE_PE32) {
		printf("PE32 file format detected\n");
		abort( fread(&pef->header.optional.standard.pe32, sizeof(pef->header.optional.standard.pe32), 1, f) != 1 );
		abort( fread(&pef->header.optional.windows.pe32, sizeof(pef->header.optional.windows.pe32), 1, f) != 1 );
		if (pef->header.optional.windows.pe32.number_of_rva_and_sizes) abort( fread(&pef->header.optional.data_directory, min(sizeof(pef->header.optional.data_directory), sizeof(pe_data_directory) * pef->header.optional.windows.pe32.number_of_rva_and_sizes), 1, f) != 1 );
	} else if (pef->header.optional.magic == PE_IMAGE_FILE_STATE_PE32P) {	
		printf("PE32+ file format detected\n");
		abort( fread(&pef->header.optional.standard.pe32p, sizeof(pef->header.optional.standard.pe32p), 1, f) != 1 );
		abort( fread(&pef->header.optional.windows.pe32p, sizeof(pef->header.optional.windows.pe32p), 1, f) != 1 );
		if (pef->header.optional.windows.pe32p.number_of_rva_and_sizes) abort( fread(&pef->header.optional.data_directory, min(sizeof(pef->header.optional.data_directory), sizeof(pe_data_directory) * pef->header.optional.windows.pe32p.number_of_rva_and_sizes), 1, f) != 1 );
	} else {
		abort( 1 );
	}

	/* load section table */
	printf("loading section table (%i)\n", pef->header.coff.number_of_sections);
	abort( fseek(f, sig_offset + sizeof(pef->header.signature) + sizeof(pef->header.coff) + pef->header.coff.size_of_optional_header, SEEK_SET) );
	if (pef->header.coff.number_of_sections) {
		pef->section_table = (pe_section_header *) malloc(sizeof(pe_section_header) * pef->header.coff.number_of_sections);
		abort( !pef->section_table );
		abort( fread(pef->section_table, sizeof(pe_section_header) * pef->header.coff.number_of_sections, 1, f) != 1 );
	}

	/* load string table */
	if (pef->header.coff.pointer_to_symbol_table && pef->header.coff.number_of_symbols) {
		printf("loading string table\n");
		abort( fseek(f, pef->header.coff.pointer_to_symbol_table + sizeof(pe_symbol) * pef->header.coff.number_of_symbols, SEEK_SET) );
		abort( fread(&pef->string_table.size, sizeof(uint32_t), 1, f) != 1 );
		pef->string_table.size -= sizeof(uint32_t);
		if (pef->string_table.size) {
			pef->string_table = pe_buffer_new(pef->string_table.size);
			abort( !pef->string_table.data );
			abort( fread(pef->string_table.data, pef->string_table.size, 1, f) != 1 );
		}
	}

	/* load sections */
	printf("loading sections\n");
	if (pef->header.coff.number_of_sections) {
		pef->section = (pe_section *) malloc(sizeof(pe_section) * pef->header.coff.number_of_sections);
		abort( !pef->section );
		memset(pef->section, 0, sizeof(pe_section) * pef->header.coff.number_of_sections);

		int i;
		for (i = 0; i < pef->header.coff.number_of_sections; i++) {
			if (pef->section_table[i].name[0] == '/') {
				abort( !pef->string_table.data );

				uint32_t offset;
				sscanf((char *) pef->section_table[i].name, "/%u", &offset);
				abort( fseek(f, offset, SEEK_SET) );
				abort( offset >= pef->string_table.size );
				pef->section[i].name = strdup((char *) pef->string_table.data + offset);
				abort( !pef->section[i].name );

			} else {
				char name[9];
				memset(name, 0, sizeof(char) * 9);
				strncpy(name, (char *) pef->section_table[i].name, sizeof(pef->section_table[i].name));
				pef->section[i].name = strdup(name);
				abort( !pef->section[i].name );
			}

			printf("loading section %s (%u bytes)\n", pef->section[i].name, pef->section_table[i].size_of_raw_data);

			if (pef->section_table[i].size_of_raw_data) {
				pef->section[i].container = pe_buffer_new(pef->section_table[i].size_of_raw_data);
				abort( !pef->section[i].container.data );
				if (pef->section_table[i].pointer_to_raw_data) {
					abort( fseek(f, pef->section_table[i].pointer_to_raw_data, SEEK_SET) );
					abort( fread(pef->section[i].container.data, pef->section[i].container.size, 1, f) != 1 );
				} else {
					memset(pef->section[i].container.data, 0, pef->section[i].container.size);
				}
			}
		}
	}

	fclose(f);

	return pef;

	abort:

	if (f) fclose(f);

	pe_file_free(pef);

	return NULL;
}

pe_buffer * pe_file_get_section_data(pe_file *pef, const char *name) {
	int i;
	for (i = 0; i < pef->header.coff.number_of_sections; i++) {
		if (!strcmp(pef->section[i].name, name)) {
			return &pef->section[i].container;
		}
	}

	return NULL;
}

pe_section_header * pe_file_get_section_header(pe_file *pef, const char *name) {
	int i;
	for (i = 0; i < pef->header.coff.number_of_sections; i++) {
		if (!strcmp(pef->section[i].name, name)) {
			return &pef->section_table[i];
		}
	}

	return NULL;
}

pe_buffer * pe_file_get_section_data_by_va(pe_file *pef, va addr) {
	int i;
	for (i = 0; i < pef->header.coff.number_of_sections; i++) {
		if (pef->header.optional.magic == PE_IMAGE_FILE_STATE_PE32) {
			va base, end;
			base = (va) pef->header.optional.windows.pe32.image_base + pef->section_table[i].virtual_address;
			end = base + pef->section_table[i].virtual_size;
			if (addr >= base && addr < end) {
				return &pef->section[i].container;
			}
		} else {
			va base, end;
			base = (va) pef->header.optional.windows.pe32p.image_base + pef->section_table[i].virtual_address;
			end = base + pef->section_table[i].virtual_size;
			if (addr >= base && addr < end) {
				return &pef->section[i].container;
			}
		}
	}

	return NULL;
}

pe_section_header * pe_file_get_section_header_by_va(pe_file *pef, va addr) {
	int i;
	for (i = 0; i < pef->header.coff.number_of_sections; i++) {
		if (pef->header.optional.magic == PE_IMAGE_FILE_STATE_PE32) {
			va base, end;
			base = (va) pef->header.optional.windows.pe32.image_base + pef->section_table[i].virtual_address;
			end = base + pef->section_table[i].virtual_size;
			if (addr >= base && addr < end) {
				return &pef->section_table[i];
			}
		} else {
			va base, end;
			base = (va) pef->header.optional.windows.pe32p.image_base + pef->section_table[i].virtual_address;
			end = base + pef->section_table[i].virtual_size;
			if (addr >= base && addr < end) {
				return &pef->section_table[i];
			}
		}
	}

	return NULL;
}

/*int main(int argc, char **argv) {
	if (argc > 1) {
		pe_file pef;
		if (pe_file_load(argv[1], &pef)) {
			printf("image base at %08X\n", pef.header.optional.windows.pe32.image_base);
			printf("base of code %08X\n", pef.header.optional.standard.pe32.base_of_code);
			if (pe_file_get_section_data(&pef, ".text")) {
				printf("loaded .text\n");
			} else {
				printf("failed to load section\n");
			}
			pe_file_free(&pef);
		} else {
			printf("failed to load PE file %s\n", argv[1]);
		}
	} else {
		printf("specify PE file to load\n");
	}
	exit(EXIT_SUCCESS);
}*/
