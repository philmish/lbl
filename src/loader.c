#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define PACKAGE "lbl"
#define PACKAGE_VERSION "0.0.1"
#include "../include/loader.h"
#include <bfd.h>

/*
 * - TODO: Implement SymbolList
 * - TODO: Implement SectionList
 * - TODO: Figure out how to split code into multiple files
 */

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
  struct Symbol *sym;

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
  struct Symbol *sym;

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
  struct Section *sec;
  SectionType sectype;

  for (bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next) {
    /*
     * TODO: Figure out if this is a problem and if this call can be replaced by
     * just extracting the flags from the section
     * */
    bfd_flags = bfd_get_section_flags(bfd_h, bfd_sec);

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
  }

  return 0;
};

static int load_binary_bfd(char *fname, struct Binary *bin, BinaryType type) {
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
  /* TODO: Implement loading symbols and sections */
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

int load_binary(char *fname, struct Binary *bin, BinaryType type) {
  return load_binary_bfd(fname, bin, type);
};
