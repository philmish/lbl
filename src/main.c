#include "../include/loader.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
  struct Binary bin;
  init_binary(&bin);
  char *fname;

  if (argc < 2) {
    printf("Usage: %s <binary>\n", argv[0]);
    return 1;
  }

  fname = argv[1];
  if (load_binary(fname, &bin) < 0) {
    return 1;
  }
  print_binary_info(&bin);
  print_binary_sections(&bin);
  print_binary_symbols(&bin);

  unload_binary(&bin);
  return 0;
}
