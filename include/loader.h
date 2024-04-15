#ifndef LOADER_H /* LOADER_H */
#define LOADER_H

#include <stdbool.h>
#include <stdint.h>

struct Symbol;

struct SymbolListNode;

struct SymbolList;
bool symbol_list_is_empty(struct SymbolList *list);
void push_symbol_to_list(struct SymbolList *list, struct Symbol *sym);
void free_symbol_list(struct SymbolList *list);

typedef enum {
  SYM_TYPE_UKN = 0,
  SYM_TYPE_FUNC = 1,
} SymbolType;

struct Section;

typedef enum {
  SEC_TYPE_NONE = 0,
  SEC_TYPE_CODE = 1,
  SEC_TYPE_DATA = 2,
} SectionType;

/*
 * Wrapper for a Section in a SectionList.
 */
struct SectionListNode;

/*
 * Singly Linked List of Sections.
 */
struct SectionList;
bool section_list_is_empty(struct SectionList *list);
struct Section *get_section_by_name(struct SectionList *list, char *name);
void push_section_to_list(struct SectionList *list, struct Section *sec);
void free_section_list(struct SectionList *list);

struct Binary;

typedef enum {
  BIN_TYPE_AUTO = 0,
  BIN_TYPE_ELF = 1,
  BIN_TYPE_PE = 2,
} BinaryType;

typedef enum {
  ARCH_NONE = 0,
  ARCH_X86 = 1,
} BinaryArch;

struct Section *get_text_section(struct Binary *bin);
void init_binary(struct Binary *bin);
int load_binary(char *fname, struct Binary *bin);
void unload_binary(struct Binary *bin);
void print_binary_info(struct Binary *bin);
void print_binary_sections(struct Binary *bin);
void print_binary_symbols(struct Binary *bin);

struct Symbol {
  SymbolType type;
  char *name;
  uint64_t addr;
};

struct SymbolListNode {
  struct Symbol *symbol;
  struct SymbolListNode *next;
};

struct SymbolList {
  struct SymbolListNode *head;
  struct SymbolListNode *tail;
};

struct Section {
  struct Binary *binary;
  char *name;
  SectionType type;
  uint64_t vma;
  uint64_t size;
  uint8_t *bytes;
};

struct SectionListNode {
  struct Section *section;
  struct SectionListNode *next;
};

struct SectionList {
  struct SectionListNode *head;
  struct SectionListNode *tail;
};

struct Binary {
  char *filename;
  BinaryType type;
  char *type_str;
  BinaryArch arch;
  char *arch_str;
  unsigned bits;
  uint64_t entry;
  struct SectionList sections;
  struct SymbolList symbols;
};

#endif /* LOADER_H */
