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

  assert(fin = fopen(argv[nbf], "r"));
  assert(fout = fopen(argv[nbf == 1 ? 3:2], "w"));

  generate_elf(fin, fout);

  fclose(fin);
  fclose(fout);

  return EXIT_SUCCESS;
}

void generate_elf(FILE *fin, FILE *fout)
{
  char bufin[0x100000];
  char bufout[0X100000];

  fread(bufin, 1, 0x400000, fin);

  Elf64_Ehdr *fhin = malloc(sizeof(Elf64_Ehdr));
  Elf64_Ehdr *fhout = malloc(sizeof(Elf64_Ehdr));

  memcpy(fhin, bufin, sizeof(Elf64_Ehdr));
  memcpy(fhout, fhin, sizeof(Elf64_Ehdr));
  fhout->e_ident[EI_OSABI] = 3;
  fhout->e_type = ET_EXEC;
  fhout->e_phoff = 0x040;
  fhout->e_phentsize = sizeof(Elf64_Phdr);
  fhout->e_shentsize = 0;//sizeof(Elf64_Shdr);

  Elf64_Phdr *phAX = malloc(sizeof(Elf64_Phdr));
  Elf64_Phdr *phA = malloc(sizeof(Elf64_Phdr));
  Elf64_Phdr *phAW = malloc(sizeof(Elf64_Phdr));

  phAX->p_type = PT_LOAD;
  phAX->p_filesz = 0;
  phAX->p_memsz = 0;
  phAX->p_align = 0x1000;

  memcpy(phA, phAX, sizeof(Elf64_Phdr));
  memcpy(phAW, phAX, sizeof(Elf64_Phdr));

  phAX->p_flags = PF_X | PF_R;
  phA->p_flags = PF_R;
  phAW->p_flags = PF_W | PF_R;

  Elf64_Shdr **shin = malloc(sizeof(Elf64_Shdr*) * fhin->e_shnum);
  Elf64_Shdr **shout = malloc(sizeof(Elf64_Shdr*) * fhin->e_shnum);

  for (size_t i = 0; i < fhin->e_shnum; ++i)
  {
    shin[i] = malloc(sizeof(Elf64_Shdr));
    memcpy(shin[i], bufin + fhin->e_shoff + i * fhin->e_shentsize, sizeof(Elf64_Shdr));
    if (shin[i]->sh_type == SHT_NOBITS)
      continue;

    shout[i] = malloc(sizeof(Elf64_Shdr));
    memcpy(shout[i], shin[i], sizeof(Elf64_Shdr));

    if ((shin[i]->sh_flags & (SHF_WRITE | SHF_ALLOC)) == (SHF_WRITE | SHF_ALLOC)) {
      phAW->p_filesz += shin[i]->sh_size;
      phAW->p_memsz += shin[i]->sh_size;
    }
    else if ((shin[i]->sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) == (SHF_ALLOC | SHF_EXECINSTR)) {
      phAX->p_filesz += shin[i]->sh_size;
      phAX->p_memsz += shin[i]->sh_size;
    }
    else if ((shin[i]->sh_flags & SHF_ALLOC) == SHF_ALLOC) {
      phA->p_filesz += shin[i]->sh_size;
      phA->p_memsz += shin[i]->sh_size;
    } else
      continue;
  }

  phAX->p_offset = 0;
  phAW->p_offset = phAX->p_filesz;
  phA->p_offset = phAW->p_offset + phAW->p_filesz;
  phAX->p_vaddr = 0x400000;
  phAW->p_vaddr = phAX->p_vaddr + phAX->p_memsz;
  phA->p_vaddr = phAW->p_vaddr + phAW->p_memsz;
  phAX->p_paddr = phAX->p_paddr;
  phAW->p_paddr = phAW->p_paddr;
  phA->p_paddr = phA->p_paddr;

  for (size_t i = 0; i < fhin->e_shnum; ++i)
  {
    if (!shout[i])
      continue;
    if ((shout[i]->sh_flags & (SHF_WRITE | SHF_ALLOC)) == (SHF_WRITE | SHF_ALLOC)) {
      shout[i]->sh_offset = phAW->p_offset + phAW->p_memsz;
    }
    else if ((shout[i]->sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) == (SHF_ALLOC | SHF_EXECINSTR)) {
      shout[i]->sh_offset = phAX->p_offset + phAX->p_memsz;
    }
    else if ((shout[i]->sh_flags & SHF_ALLOC) == SHF_ALLOC) {
      shout[i]->sh_offset = phA->p_offset + phA->p_memsz;
    }
  }

  // RELLOCATIOOOOOOOON

  fhout->e_entry = (unsigned long long)(phAX->p_vaddr | phAX->p_align | 0xDC); //DC SYMTAB
  fhout->e_shoff = 0; // phA->p_offset + phA->p_filesz;
  fhout->e_phnum = 3;
  fhout->e_shnum = 0;
  fhout->e_shstrndx = 0;// OSBLC

  size_t offset = 0;

  memcpy(bufout, fhout, sizeof(Elf64_Ehdr));
  offset += sizeof(Elf64_Ehdr);
  memcpy(bufout + offset, phAX, sizeof(Elf64_Phdr));
  offset += sizeof(Elf64_Phdr);
  memcpy(bufout + offset, phAW, sizeof(Elf64_Phdr));
  offset += sizeof(Elf64_Phdr);
  memcpy(bufout + offset, phA, sizeof(Elf64_Phdr));
  offset += sizeof(Elf64_Phdr);

  for (size_t i = 0; i < fhin->e_shnum; ++i){
    if (!shout[i])
      continue;
    memcpy(bufout + shout[i]->sh_offset, bufin + shin[i]->sh_offset, shout[i]->sh_size);
    offset += shout[i]->sh_size;
  }

  fwrite(bufout, 1, offset, fout);

  for (size_t i = 0; i < fhin->e_shnum; ++i){
    free(shin[i]);
    if (shout[i])
      free(shout[i]);
  }
  free(shin);
  free(shout);
  free(phA);
  free(phAW);
  free(phAX);
  free(fhout);
  free(fhin);
}

