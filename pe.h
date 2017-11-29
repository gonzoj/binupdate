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

#ifndef PE_H_
#define PE_H_

#include <stdint.h>
#include <unistd.h>

/*typedef union {
	uint32_t l32;
	uint64_t l64;
} va;

#define _va(pef, v) ((pef)->header.optional.magic == PE_IMAGE_FILE_STATE_PE32 ? v.l32 : v.l64)
#define va_type(pef, v) ((pef)->header.optional.magic == PE_IMAGE_FILE_STATE_PE32 ? (uint32_t) v : (uint64_t) v)*/

typedef uint64_t va;

#define _va(pef, mem) ((pef)->header.optional.magic == PE_IMAGE_FILE_STATE_PE32 ? *(uint32_t *)mem : *(uint64_t *)mem)

typedef uint32_t rva;

typedef struct {
	unsigned char *data;
	size_t size;
} pe_buffer;

#define pe_buffer_contains(peb, addr) ((addr) >= (unsigned long) (peb)->data && (addr) < (unsigned long) (peb)->data + (peb)->size)

#define PE_MSDOS_STUB_SIGNATURE_OFFSET 0x3c
#define PE_IMAGE_FILE_SIGNATURE        "PE\0\0"

typedef struct {
	uint16_t machine;
	uint16_t number_of_sections;
	uint32_t time_data_stamp;
	uint32_t pointer_to_symbol_table;
	uint32_t number_of_symbols;
	uint16_t size_of_optional_header;
	uint16_t characteristics;
} pe_file_header_coff;

#define PE_IMAGE_FILE_STATE_PE32  0x10b
#define PE_IMAGE_FILE_STATE_PE32P 0x20b

typedef struct {
	uint32_t virtual_address;
	uint32_t size;
} pe_data_directory;

typedef struct {
	uint16_t magic;
	union {
		struct __attribute__ ((__packed__)) {
			uint8_t major_linker_version;
			uint8_t minor_linker_version;
			uint32_t size_of_code;
			uint32_t size_of_initialized_data;
			uint32_t size_of_uninitialized_data;
			uint32_t address_of_entry_point;
			uint32_t base_of_code;
			uint32_t base_of_data; /* PE32 only */
		} pe32;
		struct __attribute__ ((__packed__)) {
			uint8_t major_linker_version;
			uint8_t minor_linker_version;
			uint32_t size_of_code;
			uint32_t size_of_initialized_data;
			uint32_t size_of_uninitialized_data;
			uint32_t address_of_entry_point;
			uint32_t base_of_code;
		} pe32p;
	} standard;
	union {
		struct {
			uint32_t image_base;
			uint32_t section_alignment;
			uint32_t file_alignment;
			uint16_t major_operating_system_version;
			uint16_t minor_operating_system_version;
			uint16_t major_image_version;
			uint16_t minor_image_version;
			uint16_t major_subsystem_version;
			uint16_t minor_subsystem_version;
			uint32_t win32_version_value; /* reserved, must be zero */
			uint32_t size_of_image;
			uint32_t size_of_headers;
			uint32_t check_sum;
			uint16_t subsystem;
			uint16_t dll_characteristics;
			uint32_t size_of_stack_reserve;
			uint32_t size_of_stack_commit;
			uint32_t size_of_heap_reserve;
			uint32_t size_of_heap_commit;
			uint32_t loader_flags;
			uint32_t number_of_rva_and_sizes;
		} pe32;
		struct {
			uint64_t image_base;
			uint32_t section_alignment;
			uint32_t file_alignment;
			uint16_t major_operating_system_version;
			uint16_t minor_operating_system_version;
			uint16_t major_image_version;
			uint16_t minor_image_version;
			uint16_t major_subsystem_version;
			uint16_t minor_subsystem_version;
			uint32_t win32_version_value; /* reserved, must be zero */
			uint32_t size_of_image;
			uint32_t size_of_headers;
			uint32_t check_sum;
			uint16_t subsystem;
			uint16_t dll_characteristics;
			uint64_t size_of_stack_reserve;
			uint64_t size_of_stack_commit;
			uint64_t size_of_heap_reserve;
			uint64_t size_of_heap_commit;
			uint32_t loader_flags;
			uint32_t number_of_rva_and_sizes;
		} pe32p;
	} windows;
	struct {
		pe_data_directory export_table;
		pe_data_directory import_table;
		pe_data_directory resource_table;
		pe_data_directory exception_table;
		pe_data_directory certificate_table; /* file pointer */
		pe_data_directory base_relocation_table;
		pe_data_directory debug;
		pe_data_directory architecture;
		pe_data_directory global_ptr;
		pe_data_directory tls_table;
		pe_data_directory load_config_table;
		pe_data_directory bound_import;
		pe_data_directory iat;
		pe_data_directory delay_import_descriptor;
		pe_data_directory clr_runtime_header;
		pe_data_directory reserved; /* reserved, must be zero */
	} data_directory;
} pe_file_header_optional;

#define pe_header_optional_windows(pef, member) ((pef)->header.optional.magic == PE_IMAGE_FILE_STATE_PE32 ? (pef)->header.optional.windows.pe32.member : (pef)->header.optional.windows.pe32p.member)
#define pe_header_optional_standard(pef, member) ((pef)->header.optional.magic == PE_IMAGE_FILE_STATE PE32 ? (pef)->header.optional.standard.pe32.member : (pef)->header.optional.standard.pe32p.member)

typedef struct {
	uint8_t name[8]; /* UTF-8 string or '/' followed by ASCII representation of an offset into the string table */
	uint32_t virtual_size;
	uint32_t virtual_address;
	uint32_t size_of_raw_data;
	uint32_t pointer_to_raw_data;
	uint32_t pointer_to_relocations;
	uint32_t pointer_to_line_numbers;
	uint16_t number_of_relocations;
	uint16_t number_of_line_numbers;
	uint32_t characteristics;
} pe_section_header;

#define pe_section_base(pef, sh) ((va) (pe_header_optional_windows(pef, image_base) + (sh)->virtual_address))
#define pe_section_contains(pef, sh, addr) ((addr >= (va) pe_header_optional_windows(pef, image_base) + (sh)->virtual_address) && \
					(addr < (va) pe_header_optional_windows(pef, image_base) + (sh)->virtual_address + (sh)->virtual_size))

typedef struct {
	char *name;
	pe_buffer container;
} pe_section;

#define pe_section_data_contains(buf, sh, addr) ((addr >= (unsigned long) (buf)->data) && (addr < (unsigned long) (buf)->data + (sh)->virtual_size))

typedef struct __attribute__ ((__packed__)) {
	uint8_t record[18]; /* either standard or auxiliary symbol table record */
} pe_symbol;

typedef struct {
	struct {
		pe_buffer msdos_stub; /* offset to signature at 0x3c */
		uint8_t signature[4];
		pe_file_header_coff coff;
		pe_file_header_optional optional;
	} header;
	pe_section_header *section_table;
	pe_buffer string_table; /* after symbol table 4 bytes size (including size field) followed by null-terminated strings */
	pe_section *section;
} pe_file;

pe_buffer pe_buffer_new(size_t size);

void pe_buffer_free(pe_buffer peb);

void pe_file_free(pe_file *pef);

pe_file * pe_file_load(const char *file, pe_file *pef);

pe_buffer * pe_file_get_section_data(pe_file *pef, const char *name);

pe_section_header * pe_file_get_section_header(pe_file *pef, const char *name);

pe_buffer * pe_file_get_section_data_by_va(pe_file *pef, va addr);

pe_section_header * pe_file_get_section_header_by_va(pe_file *pef, va addr);

#endif /* PE_H_ */
