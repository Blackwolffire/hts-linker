#include <elf.h>
#include <link.h>

#define NULL (void*)0

typedef void(*pfunc)(void);
typedef int (*myprintf)(const char*, ...);

char my_strcmp(const char* str1, const char* str2)
{
  if (!str1 || !str2)
    return (char)(str1 - str2);
  for (; *str1 && *str2 && *str1 == *str2; ++str1, ++str2);
  return *str1 - *str2;
}

Elf64_Phdr* get_phdy(char **env, uint64_t* baddr)
{
  Elf64_Phdr* phdr = NULL;
  Elf64_auxv_t* auxv = NULL;
  uint64_t phnum = 0;

  while (*env)
    ++env;
  auxv = (Elf64_auxv_t*)(env + 1);
  while (auxv->a_type != AT_NULL){
    if (auxv->a_type == AT_PHDR)
      phdr = (void*)auxv->a_un.a_val;
    else if (auxv->a_type == AT_PHNUM)
      phnum = auxv->a_un.a_val;
    ++auxv;
  }
  *baddr = (uint64_t)(phdr - phdr->p_vaddr);
  for (size_t i = 0; i < phnum && phdr->p_type != PT_DYNAMIC; ++i)
    ++phdr;
  return phdr;
}

void* get_debug_ptr(Elf64_Phdr* phdy, uint64_t baddr)
{
  Elf64_Dyn* dyn = (void*)(phdy->p_vaddr + baddr);
  while (dyn->d_tag != DT_DEBUG)
    ++dyn;
  return (void*)dyn->d_un.d_ptr;
}

pfunc get_func(struct link_map* lmap, const char *func, uint64_t baddr)
{
  pfunc rfun = NULL;
  Elf64_Dyn* dytab = NULL;
  Elf64_Dyn* symdyn = NULL;
  Elf64_Dyn* strdyn = NULL;

  while (lmap)
  {
    dytab = lmap->l_ld;
    symdyn = NULL;
    strdyn = NULL;

    while (dytab->d_tag != DT_NULL && (!symdyn || !strdyn))
    {
      if (dytab->d_tag == DT_SYMTAB)
        symdyn = dytab;
      else if (dytab->d_tag == DT_STRTAB)
        strdyn = dytab;
      ++dytab;
    }

    Elf64_Sym* sym = (void*)symdyn->d_un.d_ptr;
    char* strsec = (void*)(strdyn->d_un.d_ptr);

    if ((void*)sym < (void*)baddr)
      sym += baddr;
    if ((void*)strsec < (void*)baddr)
      strsec += baddr;

    while ((char*)sym < (char*)strdyn->d_un.d_ptr)
    {
      if (!my_strcmp(func, strsec + sym->st_name))
        return rfun = (pfunc)(lmap->l_addr + sym->st_value);
      ++sym;
    }
    lmap = lmap->l_next;
  }
  return NULL;
}

int main(int argc, char *argv[], char *envp[])
{
  uint64_t baddr = 0;
  (void)argc;
  (void)argv;
  Elf64_Phdr* phdy = get_phdy(envp, &baddr);
  struct r_debug* rdeg = get_debug_ptr(phdy, baddr);
  struct link_map* lmap = rdeg->r_map;
  myprintf p_printf = (myprintf)get_func(lmap, "printf", baddr);
  p_printf("hello world !\n");

  return 0;
}

