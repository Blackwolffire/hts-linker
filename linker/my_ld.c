#include <assert.h>
#include <elf.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define VBASE 0x400000

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
  chmod(argv[nbf == 1 ? 3:2], 0754);

  return EXIT_SUCCESS;
}

void setup_Ehdr(Elf64_Ehdr* fhout, Elf64_Ehdr* fhin)
{
  memcpy(fhout, fhin, sizeof(Elf64_Ehdr));
  fhout->e_ident[EI_OSABI] = 3;
  fhout->e_type = ET_EXEC;
  fhout->e_phoff = 0x040;
  fhout->e_phentsize = sizeof(Elf64_Phdr);
  fhout->e_shentsize = 0;//sizeof(Elf64_Shdr);
}

void setup_Phdr(Elf64_Phdr *phAX, Elf64_Phdr* phAW, Elf64_Phdr* phA)
{
  phAX->p_type = PT_LOAD;
  phAX->p_filesz = 0;
  phAX->p_memsz = 0;
  phAX->p_align = 0x1000;

  memcpy(phA, phAX, sizeof(Elf64_Phdr));
  memcpy(phAW, phAX, sizeof(Elf64_Phdr));

  phAX->p_flags = PF_X | PF_R;
  phA->p_flags = PF_R;
  phAW->p_flags = PF_W | PF_R;

  phAX->p_offset = 0x0000;
  phAX->p_filesz = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) * 3;
  phAX->p_memsz = phAX->p_filesz;
  phAW->p_offset = 0x1000;
  phA->p_offset = 0x2000;
}

void set_Phdr_address(Elf64_Phdr *phAX, Elf64_Phdr* phAW, Elf64_Phdr* phA)
{
  phAX->p_vaddr = VBASE + phAX->p_offset;
  phAW->p_vaddr = VBASE + phAW->p_offset;
  phA->p_vaddr = VBASE + phA->p_offset;
  phAX->p_paddr = phAX->p_vaddr;
  phAW->p_paddr = phAW->p_vaddr;
  phA->p_paddr = phA->p_vaddr;
}

size_t get_start(char* bufin, Elf64_Ehdr* fhin, Elf64_Shdr** shin,
                 Elf64_Shdr** shout, Elf64_Shdr** rsymtab)
{
  size_t entry_offset = 0;
  Elf64_Shdr *symtab;
  Elf64_Sym *sym;

  for (size_t i = 0; i < fhin->e_shnum; ++i)
  {
    if (shin[i]->sh_type == SHT_SYMTAB)
    {
      symtab = shin[i];
      for (sym = (void*)(bufin + shin[i]->sh_offset);
          (char*)sym < (char*)(bufin + shin[i]->sh_offset + shin[i]->sh_size);
          ++sym)
      {
        Elf64_Shdr* tmpstrtab = shin[shin[i]->sh_link];

        if (!strcmp("_start", bufin + tmpstrtab->sh_offset+ sym->st_name)
            && ELF64_ST_TYPE(sym->st_info) == STT_FUNC)
        {
          /*if (entry_offset)
          {
            //CHELOU - il y a plusieurs _start
          }*/
          entry_offset = shout[sym->st_shndx]->sh_offset + sym->st_value;
        }
      }
    }
  }
  *rsymtab = symtab;
  return entry_offset;
}

void recolation(char* bufin, char* bufout, Elf64_Ehdr* fhin, Elf64_Shdr** shin,
                Elf64_Shdr** shout, Elf64_Shdr* symtab)
{
  Elf64_Sym *sym;
  Elf64_Rela *rela;

  for (size_t i = 0; i < fhin->e_shnum; ++i)
  {
    if (shin[i]->sh_type == SHT_RELA)
    {
      sym = (void*)(bufin + symtab->sh_offset);

      for (rela = (void*)(bufin + shin[i]->sh_offset);
          (char*)rela < (char*)(bufin + shin[i]->sh_offset + shin[i]->sh_size);
          ++rela)
      {
        Elf64_Sym *tmpsym = sym + ELF64_R_SYM(rela->r_info);

        if (ELF64_R_TYPE(rela->r_info) == 1) // R_X86_64_64
        {
          *((uint32_t*)(bufout + shout[shin[i]->sh_info]->sh_offset
            + rela->r_offset)) = shout[tmpsym->st_shndx]->sh_offset
                               + tmpsym->st_value + VBASE + rela->r_addend;
        }
        else if (ELF64_R_TYPE(rela->r_info) == 2) // R_X86_64_PC32
        {
          *((uint32_t*)(bufout + shout[shin[i]->sh_info]->sh_offset
            + rela->r_offset)) = shout[tmpsym->st_shndx]->sh_offset
                               + tmpsym->st_value + VBASE + rela->r_addend
                               - (VBASE + shout[shin[i]->sh_info]->sh_offset
                                  + rela->r_offset);
        }
      }
    }
  }
}

void generate_elf(FILE *fin, FILE *fout)
{
  char *bufin = malloc(sizeof(char) * (1 << 22));
  char *bufout = malloc(sizeof(char) * (1 << 22));

  fread(bufin, 1, (1 << 22), fin);

  Elf64_Ehdr *fhin = malloc(sizeof(Elf64_Ehdr));
  Elf64_Ehdr *fhout = malloc(sizeof(Elf64_Ehdr));

  memcpy(fhin, bufin, sizeof(Elf64_Ehdr));
  setup_Ehdr(fhout, fhin);

  Elf64_Phdr *phAX = malloc(sizeof(Elf64_Phdr));
  Elf64_Phdr *phA = malloc(sizeof(Elf64_Phdr));
  Elf64_Phdr *phAW = malloc(sizeof(Elf64_Phdr));

  setup_Phdr(phAX, phAW, phA);

  Elf64_Shdr **shin = malloc(sizeof(Elf64_Shdr*) * fhin->e_shnum);
  Elf64_Shdr **shout = malloc(sizeof(Elf64_Shdr*) * fhin->e_shnum);

  for (size_t i = 0; i < fhin->e_shnum; ++i)
  {
    shin[i] = malloc(sizeof(Elf64_Shdr));
    memcpy(shin[i], bufin + fhin->e_shoff + i * fhin->e_shentsize, sizeof(Elf64_Shdr));
    if (shin[i]->sh_type == SHT_NOBITS){
      shout[i] = NULL;
      continue;
    }

    shout[i] = malloc(sizeof(Elf64_Shdr));
    memcpy(shout[i], shin[i], sizeof(Elf64_Shdr));

    if ((shin[i]->sh_flags & (SHF_WRITE | SHF_ALLOC)) == (SHF_WRITE | SHF_ALLOC)) {
      phAW->p_filesz += shin[i]->sh_size;
      shout[i]->sh_offset = phAW->p_offset + phAW->p_memsz;
      phAW->p_memsz += shin[i]->sh_size;
    }
    else if ((shin[i]->sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) == (SHF_ALLOC | SHF_EXECINSTR)) {
      phAX->p_filesz += shin[i]->sh_size;
      shout[i]->sh_offset = phAX->p_offset + phAX->p_memsz;
      phAX->p_memsz += shin[i]->sh_size;
    }
    else if ((shin[i]->sh_flags & SHF_ALLOC) == SHF_ALLOC
             || shin[i]->sh_type == SHT_PROGBITS) {
      phA->p_filesz += shin[i]->sh_size;
      shout[i]->sh_offset = phA->p_offset + phA->p_memsz;
      phA->p_memsz += shin[i]->sh_size;
    } else {
      free(shout[i]);
      shout[i] = NULL;
      continue;
    }
  }

  set_Phdr_address(phAX, phAW, phA);

  Elf64_Shdr *symtab;
  size_t entry_offset = get_start(bufin, fhin, shin, shout, &symtab);

  fhout->e_entry =  (phAX->p_vaddr + entry_offset);

  fhout->e_shoff = 0;
  fhout->e_phnum = 3;
  fhout->e_shnum = 0;
  fhout->e_shstrndx = 0; // OSBLC

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
    memcpy(bufout + shout[i]->sh_offset, bufin + shin[i]->sh_offset,
           shout[i]->sh_size);
    offset += shout[i]->sh_size;
  }

  offset = phA->p_offset + phA->p_filesz;

  recolation(bufin, bufout, fhin, shin, shout, symtab);

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
  free(bufout);
  free(bufin);
}

