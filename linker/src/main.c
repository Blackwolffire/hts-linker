#include <assert.h>
#include <elf.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void generate_elf(FILE *fin, FILE *fout);

int main(int argc, char *argv[])
{
  int nbf = 0;
  FILE *fin = NULL;
  FILE *fout = NULL;

  assert(argc == 4 && strcmp(argv[3], "-o"));
  if (!strcmp("-o", argv[2]))
    nbf = 1;
  else if (!strcmp("-o", argv[1]))
    nbf = 3;
  else
    assert(0);

  // parse

  assert(fin = fopen(argv[nbf], "r"));
  assert(fout = fopen(argv[nbf == 1 ? 3:2], "w"));

  // genere elf

  generate_elf(fin, fout);

  fclose(fin);
  fclose(fout);

  return EXIT_SUCCESS;
}

void generate_elf(FILE *fin, FILE *fout)
{
  char bufin[0x400000];
  char bufout[0X400000];
  // 32
  (void)bufout;
  fread(bufin, 1, 0x400000, fin);
  Elf64_Ehdr *fhedin = malloc(sizeof(Elf64_Ehdr));
  Elf64_Ehdr *fhedout = malloc(sizeof(Elf64_Ehdr));
  memcpy(fhedout->e_ident, bufin, EI_NIDENT);
  memcpy(fhedin->e_ident, bufin, EI_NIDENT);
  fhedout->e_type = ET_EXEC;
  fhedout->e_machine = fhedin->e_machine;
  fwrite(fhed, sizeof(Elf64_Ehdr), 1, fout);
}
