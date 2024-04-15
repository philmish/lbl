#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PACKAGE "lbl"
#define PACKAGE_VERSION "0.0.1"
#include "../include/loader.h"
#include <bfd.h>

bool symbol_list_is_empty(struct SymbolList *list) {
  return (list->head == NULL) && (list->tail == NULL);
};

void free_symbol_list(struct SymbolList *list) {
  struct SymbolListNode *current = list->head;
  struct SymbolListNode *tmp;

  while (current) {
    tmp = current;
    current = tmp->next;
    free(tmp);
  }
};

void push_symbol_to_list(struct SymbolList *list, struct Symbol *sym) {
  struct SymbolListNode *node =
      (struct SymbolListNode *)malloc(sizeof(struct SymbolListNode));
  node->symbol = sym;
  node->next = NULL;
  if (symbol_list_is_empty(list)) {
    list->head = node;
    list->tail = list->head;
  } else {
    list->tail->next = node;
    list->tail = node;
  }
};

bool section_list_is_empty(struct SectionList *list) {
  return (list->head == NULL) && (list->tail == NULL);
};

void free_section_list(struct SectionList *list) {
  struct SectionListNode *current = list->head;
  struct SectionListNode *tmp;

  while (current) {
    tmp = current;
    current = tmp->next;
    if (tmp->section->bytes) {
      free(tmp->section->bytes);
    }
    free(tmp);
  }
};

struct Section *get_section_by_name(struct SectionList *list, char *name) {
  struct SectionListNode *current = list->head;

  while (current) {
    if (strcmp(name, current->section->name) == 0) {
      return current->section;
    }
    current = current->next;
  }
  return NULL;
};

void push_section_to_list(struct SectionList *list, struct Section *sec) {
  struct SectionListNode *node =
      (struct SectionListNode *)malloc(sizeof(struct SectionListNode));
  node->section = sec;
  node->next = NULL;

  if (section_list_is_empty(list)) {
    list->head = node;
    list->tail = list->head;
  } else {
    list->tail->next = node;
    list->tail = node;
  }
};

static bfd *open_bfd(char *fname) {
  static int bfd_is_initialized = 0;
  bfd *bfd_h;

  if (!bfd_is_initialized) {
    bfd_init();
    bfd_is_initialized = 1;
  };
  bfd_h = bfd_openr(fname, NULL);

  if (!bfd_h) {
    fprintf(stderr, "failed to open binary file: '%s' (%s)\n", fname,
            bfd_errmsg(bfd_get_error()));
    return NULL;
  };

  if (!bfd_check_format(bfd_h, bfd_object)) {
    fprintf(stderr, "file '%s' does not look like an executable (%s)\n", fname,
            bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  /*
   * The original code suggests that sometimes sets an error status during
   * error detection and forgets to unset it.
   * To prevent problems with that we manually set the error to no error.
   */
  bfd_set_error(bfd_error_no_error);

  if (bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour) {
    fprintf(stderr, "unrecognized binary format in '%s' (%s)", fname,
            bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  return bfd_h;
};

static int load_symbols_bfd(bfd *bfd_h, struct Binary *bin) {
  int ret;
  long n, nsyms, i;
  asymbol **bfd_symtab;

  bfd_symtab = NULL;

  n = bfd_get_symtab_upper_bound(bfd_h);
  if (n < 0) {
    fprintf(stderr, "failed to read symtab (%s)\n",
            bfd_errmsg(bfd_get_error()));
    goto fail;
  } else if (n) {
    bfd_symtab = (asymbol **)malloc(n);
    if (!bfd_symtab) {
      fprintf(stderr, "out of memory\n");
      goto fail;
    }
    nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
    if (nsyms < 0) {
      fprintf(stderr, "failed to read symtab (%s)\n",
              bfd_errmsg(bfd_get_error()));
      goto fail;
    }

    for (i = 0; i < nsyms; i++) {
      if (bfd_symtab[i]->flags & BSF_FUNCTION) {
        struct Symbol *temp = (struct Symbol *)malloc(sizeof(struct Symbol));
        temp->type = SYM_TYPE_FUNC;
        temp->name = (char *)bfd_symtab[i]->name;
        temp->addr = bfd_asymbol_value(bfd_symtab[i]);
        push_symbol_to_list(&bin->symbols, temp);
      };
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;
cleanup:
  if (bfd_symtab) {
    free(bfd_symtab);
  }

  return ret;
};

static int load_dynsym_bfd(bfd *bfd_h, struct Binary *bin) {
  int ret;
  long n, nsyms, i;
  asymbol **bfd_dynsym;

  bfd_dynsym = NULL;

  n = bfd_get_dynamic_symtab_upper_bound(bfd_h);
  if (n < 0) {
    fprintf(stderr, "failed to read dynamic symtab (%s)\n",
            bfd_errmsg(bfd_get_error()));
    goto fail;
  } else if (n) {
    bfd_dynsym = (asymbol **)malloc(n);
    if (!bfd_dynsym) {
      fprintf(stderr, "out of memory\n");
      goto fail;
    }
    nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym);
    if (nsyms < 0) {
      fprintf(stderr, "failed to read dynamic symtab (%s)\n",
              bfd_errmsg(bfd_get_error()));
      goto fail;
    }

    for (i = 0; i < nsyms; i++) {
      if (bfd_dynsym[i]->flags & BSF_FUNCTION) {
        struct Symbol *temp = (struct Symbol *)malloc(sizeof(struct Symbol));
        temp->type = SYM_TYPE_FUNC;
        temp->name = (char *)bfd_dynsym[i]->name;
        temp->addr = bfd_asymbol_value(bfd_dynsym[i]);
        push_symbol_to_list(&bin->symbols, temp);
      };
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;
cleanup:
  if (bfd_dynsym) {
    free(bfd_dynsym);
  }

  return ret;
};

static int load_sections_bfd(bfd *bfd_h, struct Binary *bin) {
  int bfd_flags;
  uint64_t vma, size;
  const char *secname;
  asection *bfd_sec;
  SectionType sectype;

  for (bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next) {
    /*
     * The Book uses the `bfd_get_section_flags` function here.
     * This function seems to have been renamed to `bfd_section_flags`,
     * as of this bug report from `binutils`:
     * https://bugs.archlinux.org/task/65881
     */
    bfd_flags = bfd_section_flags(bfd_sec);

    sectype = SEC_TYPE_NONE;
    if (bfd_flags & SEC_CODE) {
      sectype = SEC_TYPE_CODE;
    } else if (bfd_flags & SEC_DATA) {
      sectype = SEC_TYPE_DATA;
    } else {
      continue;
    }

    vma = bfd_section_vma(bfd_sec);
    size = bfd_section_size(bfd_sec);
    secname = bfd_section_name(bfd_sec);
    if (!secname) {
      secname = "<unnamed>";
    }

    struct Section *temp = (struct Section *)malloc(sizeof(struct Section));
    temp->binary = bin;
    temp->name = (char *)secname;
    temp->type = sectype;
    temp->vma = vma;
    temp->size = size;
    temp->bytes = (uint8_t *)malloc(size);
    if (!temp->bytes) {
      fprintf(stderr, "out of memory\n");
      return -1;
    }

    if (!bfd_get_section_contents(bfd_h, bfd_sec, temp->bytes, 0, size)) {
      fprintf(stderr, "failed tp read section '%s' (%s)\n", secname,
              bfd_errmsg(bfd_get_error()));
      return -1;
    }
    push_section_to_list(&bin->sections, temp);
  }

  return 0;
};

static int load_binary_bfd(char *fname, struct Binary *bin) {
  int ret;
  bfd *bfd_h;
  const bfd_arch_info_type *bfd_info;

  bfd_h = NULL;
  bfd_h = open_bfd(fname);
  if (!bfd_h) {
    goto fail;
  }

  bin->filename = fname;
  bin->entry = bfd_get_start_address(bfd_h);
  bin->type_str = (char *)bfd_h->xvec->name;

  switch (bfd_h->xvec->flavour) {
  case bfd_target_elf_flavour:
    bin->type = BIN_TYPE_ELF;
    break;
  case bfd_target_coff_flavour:
    bin->type = BIN_TYPE_PE;
    break;
  case bfd_target_unknown_flavour:
  default:
    fprintf(stderr, "unsupported binary type (%s)\n", bfd_h->xvec->name);
    goto fail;
  }

  bfd_info = bfd_get_arch_info(bfd_h);
  bin->arch_str = (char *)bfd_info->printable_name;
  switch (bfd_info->mach) {
  case bfd_mach_i386_i386:
    bin->arch = ARCH_X86;
    bin->bits = 32;
    break;
  case bfd_mach_x86_64:
    bin->arch = ARCH_X86;
    bin->bits = 64;
    break;
  default:
    fprintf(stderr, "unsupported architecture (%s)\n",
            bfd_info->printable_name);
    goto fail;
  }
  load_symbols_bfd(bfd_h, bin);
  load_dynsym_bfd(bfd_h, bin);

  if (load_sections_bfd(bfd_h, bin) < 0) {
    goto fail;
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if (bfd_h) {
    bfd_close(bfd_h);
  };

  return ret;
};

struct Section *get_text_section(struct Binary *bin) {
  struct Section *sec = NULL;
  if (section_list_is_empty(&bin->sections)) {
    return sec;
  };
  return get_section_by_name(&bin->sections, ".text");
};

void init_binary(struct Binary *bin) {
  struct SymbolList syms = {NULL, NULL};
  struct SectionList secs = {NULL, NULL};
  bin->sections = secs;
  bin->symbols = syms;
};

int load_binary(char *fname, struct Binary *bin) {
  return load_binary_bfd(fname, bin);
};

void unload_binary(struct Binary *bin) {
  free_symbol_list(&bin->symbols);
  free_section_list(&bin->sections);
};

void print_binary_info(struct Binary *bin) {
  printf("loaded binary '%s' %s/%s (%u bits) entry@0x%016jx\n", bin->filename,
         bin->type_str, bin->arch_str, bin->bits, bin->entry);
};

void print_binary_sections(struct Binary *bin) {
  if (section_list_is_empty(&bin->sections)) {
    printf("no sections loaded\n");
  } else {
    printf("Loaded Sections:\n");
    struct SectionListNode *current = bin->sections.head;
    while (current) {
      printf(" 0x%016jx %-8ju %-20s %s\n", current->section->vma,
             current->section->size, current->section->name,
             current->section->type == SEC_TYPE_CODE ? "CODE" : "DATA");
      current = current->next;
    }
  }
};

void print_binary_symbols(struct Binary *bin) {
  if (symbol_list_is_empty(&bin->symbols)) {
    printf("no symbols loaded\n");
  } else {
    printf("Loaded Symbols:\n");
    struct SymbolListNode *current = bin->symbols.head;
    while (current) {
      printf(" %-40s 0x%016jx %s\n", current->symbol->name,
             current->symbol->addr,
             (current->symbol->type & SYM_TYPE_FUNC) ? "FUNC" : "");
      current = current->next;
    }
  }
};
