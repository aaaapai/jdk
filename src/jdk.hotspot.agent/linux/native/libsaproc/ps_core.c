/*
 * Copyright (c) 2003, 2026, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */

#include <jni.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <elf.h>
#include <link.h>
#include <errno.h>
#include <sys/sendfile.h>
#include <sys/utsname.h>
#include "libproc_impl.h"
#include "ps_core_common.h"
#include "proc_service.h"
#include "salibelf.h"

// HWCAP_PACA was introduced in glibc 2.30
// https://sourceware.org/git/?p=glibc.git;a=commit;h=a2e57f89a35e6056c9488428e68c4889e114ef71
#if defined(__aarch64__) && !defined(HWCAP_PACA)
#define HWCAP_PACA (1 << 30)
#endif

#ifdef __ANDROID__
#include <stdio.h>
#include <ctype.h>
#include <sys/user.h>
#endif
#if defined(__ANDROID__) && !defined(PRSTATUS_T_DEFINED)
#define PRSTATUS_T_DEFINED 1
typedef struct prstatus {
    struct elf_siginfo pr_info;
    short int pr_cursig;
    unsigned int pr_sigpend;
    unsigned int pr_sighold;
    pid_t pr_pid;
    pid_t pr_ppid;
    pid_t pr_pgrp;
    pid_t pr_sid;
    struct timeval pr_utime;
    struct timeval pr_stime;
    struct timeval pr_cutime;
    struct timeval pr_cstime;
    elf_gregset_t pr_reg;
    int pr_fpvalid;
} prstatus_t;

#endif // __ANDROID__ && !PRSTATUS_T_DEFINED


// This file has the libproc implementation to read core files.
// For live processes, refer to ps_proc.c. Portions of this is adapted
// /modelled after Solaris libproc.so (in particular Pcore.c)


//---------------------------------------------------------------------------
// functions to handle map_info

// Order mappings based on virtual address.  We use this function as the
// callback for sorting the array of map_info pointers.
static int core_cmp_mapping(const void *lhsp, const void *rhsp)
{
  const map_info *lhs = *((const map_info **)lhsp);
  const map_info *rhs = *((const map_info **)rhsp);

  if (lhs->vaddr == rhs->vaddr) {
    return (0);
  }

  return (lhs->vaddr < rhs->vaddr ? -1 : 1);
}

// we sort map_info by starting virtual address so that we can do
// binary search to read from an address.
static bool sort_map_array(struct ps_prochandle* ph) {
  size_t num_maps = ph->core->num_maps;
  map_info* map = ph->core->maps;
  int i = 0;

  // allocate map_array
  map_info** array;
  if ( (array = (map_info**) malloc(sizeof(map_info*) * num_maps)) == NULL) {
    print_error("can't allocate memory for map array\n");
    return false;
  }

  // add maps to array
  while (map) {
    array[i] = map;
    i++;
    map = map->next;
  }

  // sort is called twice. If this is second time, clear map array
  if (ph->core->map_array) {
    free(ph->core->map_array);
  }

  ph->core->map_array = array;
  // sort the map_info array by base virtual address.
  qsort(ph->core->map_array, ph->core->num_maps, sizeof (map_info*),
        core_cmp_mapping);

  // print map
  if (is_debug()) {
    int j = 0;
    print_debug("---- sorted virtual address map ----\n");
    for (j = 0; j < ph->core->num_maps; j++) {
      print_debug("base = 0x%lx\tsize = %zu\n", ph->core->map_array[j]->vaddr,
                  ph->core->map_array[j]->memsz);
    }
  }

  return true;
}

#ifndef MIN
#define MIN(x, y) (((x) < (y))? (x): (y))
#endif

static bool core_read_data(struct ps_prochandle* ph, uintptr_t addr, char *buf, size_t size) {
   ssize_t resid = size;
   int page_size=sysconf(_SC_PAGE_SIZE);
   while (resid != 0) {
      map_info *mp = core_lookup(ph, addr);
      uintptr_t mapoff;
      ssize_t len, rem;
      off_t off;
      int fd;

      if (mp == NULL) {
         break;  /* No mapping for this address */
      }

      fd = mp->fd;
      mapoff = addr - mp->vaddr;
      len = MIN(resid, mp->memsz - mapoff);
      off = mp->offset + mapoff;

      if ((len = pread(fd, buf, len, off)) <= 0) {
         break;
      }

      resid -= len;
      addr += len;
      buf = (char *)buf + len;

      // mappings always start at page boundary. But, may end in fractional
      // page. fill zeros for possible fractional page at the end of a mapping.
      rem = mp->memsz % page_size;
      if (rem > 0) {
         rem = page_size - rem;
         len = MIN(resid, rem);
         resid -= len;
         addr += len;
         // we are not assuming 'buf' to be zero initialized.
         memset(buf, 0, len);
         buf += len;
      }
   }

   if (resid) {
      print_debug("core read failed for %d byte(s) @ 0x%lx (%d more bytes)\n",
              size, addr, resid);
      return false;
   } else {
      return true;
   }
}

// null implementation for write
static bool core_write_data(struct ps_prochandle* ph,
                             uintptr_t addr, const char *buf , size_t size) {
   return false;
}

static bool core_get_lwp_regs(struct ps_prochandle* ph, lwpid_t lwp_id,
                          struct user_regs_struct* regs) {
   // for core we have cached the lwp regs from NOTE section
   thread_info* thr = ph->threads;
   while (thr) {
     if (thr->lwp_id == lwp_id) {
       memcpy(regs, &thr->regs, sizeof(struct user_regs_struct));
       return true;
     }
     thr = thr->next;
   }
   return false;
}

static ps_prochandle_ops core_ops = {
   .release=  core_release,
   .p_pread=  core_read_data,
   .p_pwrite= core_write_data,
   .get_lwp_regs= core_get_lwp_regs
};

// read regs and create thread from NT_PRSTATUS entries from core file
static bool core_handle_prstatus(struct ps_prochandle* ph, const char* buf, size_t nbytes) {
   // we have to read prstatus_t from buf
   // assert(nbytes == sizeof(prstaus_t), "size mismatch on prstatus_t");
   thread_info* newthr;
   prstatus_t* prstat = (prstatus_t*) buf;
   print_debug("got integer regset for lwp %d\n", prstat->pr_pid);
   if((newthr = add_thread_info(ph, prstat->pr_pid)) == NULL) {
      print_error("failed to add thread info\n");
      return false;
   }

   // copy regs
   memcpy(&newthr->regs, prstat->pr_reg, sizeof(struct user_regs_struct));

   if (is_debug()) {
      print_debug("integer regset\n");

#if defined(amd64) || defined(x86_64)
      // print the regset
      print_debug("\tr15 = 0x%lx\n", newthr->regs.r15);
      print_debug("\tr14 = 0x%lx\n", newthr->regs.r14);
      print_debug("\tr13 = 0x%lx\n", newthr->regs.r13);
      print_debug("\tr12 = 0x%lx\n", newthr->regs.r12);
      print_debug("\trbp = 0x%lx\n", newthr->regs.rbp);
      print_debug("\trbx = 0x%lx\n", newthr->regs.rbx);
      print_debug("\tr11 = 0x%lx\n", newthr->regs.r11);
      print_debug("\tr10 = 0x%lx\n", newthr->regs.r10);
      print_debug("\tr9 = 0x%lx\n", newthr->regs.r9);
      print_debug("\tr8 = 0x%lx\n", newthr->regs.r8);
      print_debug("\trax = 0x%lx\n", newthr->regs.rax);
      print_debug("\trcx = 0x%lx\n", newthr->regs.rcx);
      print_debug("\trdx = 0x%lx\n", newthr->regs.rdx);
      print_debug("\trsi = 0x%lx\n", newthr->regs.rsi);
      print_debug("\trdi = 0x%lx\n", newthr->regs.rdi);
      print_debug("\torig_rax = 0x%lx\n", newthr->regs.orig_rax);
      print_debug("\trip = 0x%lx\n", newthr->regs.rip);
      print_debug("\tcs = 0x%lx\n", newthr->regs.cs);
      print_debug("\teflags = 0x%lx\n", newthr->regs.eflags);
      print_debug("\trsp = 0x%lx\n", newthr->regs.rsp);
      print_debug("\tss = 0x%lx\n", newthr->regs.ss);
      print_debug("\tfs_base = 0x%lx\n", newthr->regs.fs_base);
      print_debug("\tgs_base = 0x%lx\n", newthr->regs.gs_base);
      print_debug("\tds = 0x%lx\n", newthr->regs.ds);
      print_debug("\tes = 0x%lx\n", newthr->regs.es);
      print_debug("\tfs = 0x%lx\n", newthr->regs.fs);
      print_debug("\tgs = 0x%lx\n", newthr->regs.gs);
#endif
   }

   return true;
}

#define ROUNDUP(x, y)  ((((x)+((y)-1))/(y))*(y))

// read NT_PRSTATUS entries from core NOTE segment
static bool core_handle_note(struct ps_prochandle* ph, ELF_PHDR* note_phdr) {
   char* buf = NULL;
   char* p = NULL;
   size_t size = note_phdr->p_filesz;

   // we are interested in just prstatus entries. we will ignore the rest.
   // Advance the seek pointer to the start of the PT_NOTE data
   if (lseek(ph->core->core_fd, note_phdr->p_offset, SEEK_SET) == (off_t)-1) {
      print_error("failed to lseek to PT_NOTE data\n");
      return false;
   }

   // Now process the PT_NOTE structures.  Each one is preceded by
   // an Elf{32/64}_Nhdr structure describing its type and size.
   if ( (buf = (char*) malloc(size)) == NULL) {
      print_error("can't allocate memory for reading core notes\n");
      goto err;
   }

   // read notes into buffer
   if (read(ph->core->core_fd, buf, size) != size) {
      print_error("failed to read notes, core file must have been truncated\n");
      goto err;
   }

   p = buf;
   while (p < buf + size) {
      ELF_NHDR* notep = (ELF_NHDR*) p;
      char* descdata  = p + sizeof(ELF_NHDR) + ROUNDUP(notep->n_namesz, 4);
      print_debug("Note header with n_type = %d and n_descsz = %u\n",
                                   notep->n_type, notep->n_descsz);

      if (notep->n_type == NT_PRSTATUS) {
        if (core_handle_prstatus(ph, descdata, notep->n_descsz) != true) {
          print_error("failed to handle NT_PRSTATUS note\n");
          goto err;
        }
      } else if (notep->n_type == NT_AUXV) {
        // Get first segment from entry point
        ELF_AUXV *auxv = (ELF_AUXV *)descdata;
        while (auxv->a_type != AT_NULL) {
          if (auxv->a_type == AT_ENTRY) {
            // Set entry point address to address of dynamic section.
            // We will adjust it in read_exec_segments().
            ph->core->dynamic_addr = auxv->a_un.a_val;
            break;
          } else if (auxv->a_type == AT_SYSINFO_EHDR) {
            ph->core->vdso_addr = auxv->a_un.a_val;
#ifdef __aarch64__
          } else if (auxv->a_type == AT_HWCAP) {
            ph->pac_enabled = auxv->a_un.a_val & HWCAP_PACA;
#endif
          }
          auxv++;
        }
      }
      p = descdata + ROUNDUP(notep->n_descsz, 4);
   }

   free(buf);
   return true;

err:
   if (buf) free(buf);
   return false;
}

// read all segments from core file
static bool read_core_segments(struct ps_prochandle* ph, ELF_EHDR* core_ehdr) {
   int i = 0;
   ELF_PHDR* phbuf = NULL;
   ELF_PHDR* core_php = NULL;

   if ((phbuf = read_program_header_table(ph->core->core_fd, core_ehdr)) == NULL) {
      print_error("failed to read program header table\n");
      return false;
   }

   /*
    * Now iterate through the program headers in the core file.
    * We're interested in two types of Phdrs: PT_NOTE (which
    * contains a set of saved /proc structures), and PT_LOAD (which
    * represents a memory mapping from the process's address space).
    *
    * Difference b/w Solaris PT_NOTE and Linux/BSD PT_NOTE:
    *
    *     In Solaris there are two PT_NOTE segments the first PT_NOTE (if present)
    *     contains /proc structs in the pre-2.6 unstructured /proc format. the last
    *     PT_NOTE has data in new /proc format.
    *
    *     In Solaris, there is only one pstatus (process status). pstatus contains
    *     integer register set among other stuff. For each LWP, we have one lwpstatus
    *     entry that has integer regset for that LWP.
    *
    *     Linux threads are actually 'clone'd processes. To support core analysis
    *     of "multithreaded" process, Linux creates more than one pstatus (called
    *     "prstatus") entry in PT_NOTE. Each prstatus entry has integer regset for one
    *     "thread". Please refer to Linux kernel src file 'fs/binfmt_elf.c', in particular
    *     function "elf_core_dump".
    */

    for (core_php = phbuf, i = 0; i < core_ehdr->e_phnum; i++) {
      switch (core_php->p_type) {
         case PT_NOTE:
            if (core_handle_note(ph, core_php) != true) {
              print_error("failed to read note segment\n");
              goto err;
            }
            break;

         case PT_LOAD: {
            if (core_php->p_filesz != 0) {
               if (add_map_info(ph, ph->core->core_fd, core_php->p_offset,
                     core_php->p_vaddr, core_php->p_filesz, core_php->p_flags) == NULL) {
                  print_error("failed to add map info\n");
                  goto err;
               }
               if (core_php->p_vaddr == ph->core->vdso_addr) {
                  ph->core->vdso_offset = core_php->p_offset;
                  ph->core->vdso_size = core_php->p_memsz;
               }
            }
            break;
         }
      }

      core_php++;
   }

   free(phbuf);
   return true;
err:
   free(phbuf);
   return false;
}

// read segments of a shared object
static bool read_lib_segments(struct ps_prochandle* ph, int lib_fd, ELF_EHDR* lib_ehdr, uintptr_t lib_base) {
  int i = 0;
  ELF_PHDR* phbuf;
  ELF_PHDR* lib_php = NULL;

  int page_size = sysconf(_SC_PAGE_SIZE);

  if ((phbuf = read_program_header_table(lib_fd, lib_ehdr)) == NULL) {
    print_error("failed to read program header table\n");
    return false;
  }

  // we want to process only PT_LOAD segments that are not writable.
  // i.e., text segments. The read/write/exec (data) segments would
  // have been already added from core file segments.
  for (lib_php = phbuf, i = 0; i < lib_ehdr->e_phnum; i++) {
    if ((lib_php->p_type == PT_LOAD) && !(lib_php->p_flags & PF_W) && (lib_php->p_filesz != 0)) {

      uintptr_t target_vaddr = lib_php->p_vaddr + lib_base;
      map_info *existing_map = core_lookup(ph, target_vaddr);

      if (existing_map == NULL){
        if (add_map_info(ph, lib_fd, lib_php->p_offset,
                         target_vaddr, lib_php->p_memsz, lib_php->p_flags) == NULL) {
          print_error("failed to add map info\n");
          goto err;
        }
      } else if (lib_php->p_flags != existing_map->flags) {
        // Access flags for this memory region are different between the library
        // and coredump. It might be caused by mprotect() call at runtime.
        // We should respect the coredump.
        continue;
      } else {
        // Read only segments in ELF should not be any different from PT_LOAD segments
        // in the coredump.
        // Also the first page of the ELF header might be included
        // in the coredump (See JDK-7133122).
        // Thus we need to replace the PT_LOAD segment with the library version.
        //
        // Coredump stores value of p_memsz elf field
        // rounded up to page boundary.

        // Account for the PH being at some vaddr offset from mapping in core file.
        uint64_t lib_memsz = lib_php->p_memsz;
        if (target_vaddr > existing_map->vaddr) {
            lib_memsz += target_vaddr - existing_map->vaddr;
        }
        uint64_t aligned_lib_memsz = ROUNDUP(lib_memsz, page_size);
        size_t aligned_segment_sz = ROUNDUP(lib_php->p_memsz, page_size);

        if (target_vaddr == ph->core->vdso_addr) {
          // We can overwrite with entire vDSO because vDSO on memory is
          // entire ELF binary.
          aligned_lib_memsz = ROUNDUP(existing_map->memsz, page_size);
          aligned_segment_sz = aligned_lib_memsz;
        }
        if ((existing_map->memsz != page_size) &&
            (existing_map->fd != lib_fd) &&
            (ROUNDUP(existing_map->memsz, page_size) != aligned_lib_memsz)) {

          print_error("address conflict @ 0x%lx (existing map size = %ld, size = %ld, flags = %d)\n",
                        target_vaddr, existing_map->memsz, lib_php->p_memsz, lib_php->p_flags);
          goto err;
        }

        /* replace PT_LOAD segment with library segment */
        print_debug("overwrote with new address mapping (memsz %ld -> %ld)\n",
                     existing_map->memsz, aligned_segment_sz);

        existing_map->fd = lib_fd;
        existing_map->offset = lib_php->p_offset;
        existing_map->memsz = aligned_segment_sz;
      }
    }

    lib_php++;
  }

  free(phbuf);
  return true;
err:
  free(phbuf);
  return false;
}

// process segments from interpreter (ld.so or ld-linux.so)
static bool read_interp_segments(struct ps_prochandle* ph) {
  ELF_EHDR interp_ehdr;

  if (read_elf_header(ph->core->interp_fd, &interp_ehdr) != true) {
    print_error("interpreter is not a valid ELF file\n");
    return false;
  }

  if (read_lib_segments(ph, ph->core->interp_fd, &interp_ehdr, ph->core->ld_base_addr) != true) {
    print_error("can't read segments of interpreter\n");
    return false;
  }

  return true;
}

// process segments of an a.out
// returns base address of executable.
static uintptr_t read_exec_segments(struct ps_prochandle* ph, ELF_EHDR* exec_ehdr) {
  int i = 0;
  ELF_PHDR* phbuf = NULL;
  ELF_PHDR* exec_php = NULL;
  uintptr_t result = 0L;

  if ((phbuf = read_program_header_table(ph->core->exec_fd, exec_ehdr)) == NULL) {
    print_error("failed to read program header table\n");
    return 0L;
  }

  for (exec_php = phbuf, i = 0; i < exec_ehdr->e_phnum; i++) {
    switch (exec_php->p_type) {

      // add mappings for PT_LOAD segments
    case PT_LOAD: {
      // add only non-writable segments of non-zero filesz
      if (!(exec_php->p_flags & PF_W) && exec_php->p_filesz != 0) {
        if (add_map_info(ph, ph->core->exec_fd, exec_php->p_offset, exec_php->p_vaddr, exec_php->p_filesz, exec_php->p_flags) == NULL) {
          print_error("failed to add map info\n");
          goto err;
        }
      }
      break;
    }

    // read the interpreter and it's segments
    case PT_INTERP: {
      char interp_name[BUF_SIZE + 1];

      // BUF_SIZE is PATH_MAX + NAME_MAX + 1.
      if (exec_php->p_filesz > BUF_SIZE) {
        print_error("Invalid ELF interpreter info\n");
        goto err;
      }
      if (pread(ph->core->exec_fd, interp_name,
                exec_php->p_filesz, exec_php->p_offset) != exec_php->p_filesz) {
        print_error("Unable to read in the ELF interpreter\n");
        goto err;
      }
      interp_name[exec_php->p_filesz] = '\0';
      print_debug("ELF interpreter %s\n", interp_name);
      // read interpreter segments as well
      if ((ph->core->interp_fd = pathmap_open(interp_name)) < 0) {
        print_error("can't open runtime loader\n");
        goto err;
      }
      break;
    }

    // from PT_DYNAMIC we want to read address of first link_map addr
    case PT_DYNAMIC: {
      if (exec_ehdr->e_type == ET_EXEC) {
        result = exec_php->p_vaddr;
        ph->core->dynamic_addr = exec_php->p_vaddr;
      } else { // ET_DYN
        // Base address of executable is based on entry point (AT_ENTRY).
        result = ph->core->dynamic_addr - exec_ehdr->e_entry;

        // dynamic_addr has entry point of executable.
        // Thus we should subtract it.
        ph->core->dynamic_addr += exec_php->p_vaddr - exec_ehdr->e_entry;
      }
      print_debug("address of _DYNAMIC is 0x%lx\n", ph->core->dynamic_addr);
      break;
    }

    } // switch
    exec_php++;
  } // for

  free(phbuf);
  return result;
 err:
  free(phbuf);
  return 0L;
}


#define FIRST_LINK_MAP_OFFSET offsetof(struct r_debug,  r_map)
#define LD_BASE_OFFSET        offsetof(struct r_debug,  r_ldbase)
#define LINK_MAP_ADDR_OFFSET  offsetof(struct link_map, l_addr)
#define LINK_MAP_NAME_OFFSET  offsetof(struct link_map, l_name)
#define LINK_MAP_LD_OFFSET    offsetof(struct link_map, l_ld)
#define LINK_MAP_NEXT_OFFSET  offsetof(struct link_map, l_next)

#define INVALID_LOAD_ADDRESS -1L
#define ZERO_LOAD_ADDRESS 0x0L

// Calculate the load address of shared library
// on prelink-enabled environment.
//
// In case of GDB, it would be calculated by offset of link_map.l_ld
// and the address of .dynamic section.
// See GDB implementation: lm_addr_check @ solib-svr4.c
static uintptr_t calc_prelinked_load_address(struct ps_prochandle* ph, int lib_fd, ELF_EHDR* elf_ehdr, uintptr_t link_map_addr) {
  ELF_PHDR *phbuf;
  uintptr_t lib_ld;
  uintptr_t lib_dyn_addr = 0L;
  uintptr_t load_addr;
  int i;

  phbuf = read_program_header_table(lib_fd, elf_ehdr);
  if (phbuf == NULL) {
    print_error("can't read program header of shared object\n");
    return INVALID_LOAD_ADDRESS;
  }

  // Get the address of .dynamic section from shared library.
  for (i = 0; i < elf_ehdr->e_phnum; i++) {
    if (phbuf[i].p_type == PT_DYNAMIC) {
      lib_dyn_addr = phbuf[i].p_vaddr;
      break;
    }
  }

  free(phbuf);

  if (ps_pdread(ph, (psaddr_t)link_map_addr + LINK_MAP_LD_OFFSET,
               &lib_ld, sizeof(uintptr_t)) != PS_OK) {
    print_error("can't read address of dynamic section in shared object\n");
    return INVALID_LOAD_ADDRESS;
  }

  // Return the load address which is calculated by the address of .dynamic
  // and link_map.l_ld .
  load_addr = lib_ld - lib_dyn_addr;
  print_debug("lib_ld = 0x%lx, lib_dyn_addr = 0x%lx -> lib_base_diff = 0x%lx\n", lib_ld, lib_dyn_addr, load_addr);
  return load_addr;
}

static int handle_vdso_internal(struct ps_prochandle* ph, char* vdso_name, char* lib_name, size_t lib_name_len) {
  int lib_fd;
  struct utsname uts;
  uname(&uts);

  char *vdso_path = (char*)malloc(lib_name_len);
  snprintf(vdso_path, lib_name_len, "/lib/modules/%s/vdso/%s", uts.release, vdso_name);
  print_debug("Try to open vDSO: %s\n", vdso_path);
  lib_fd = pathmap_open(vdso_path);
  if (lib_fd != -1) {
    print_debug("replace vDSO: %s -> %s\n", lib_name, vdso_path);
    strncpy(lib_name, vdso_path, lib_name_len);
  }

  free(vdso_path);
  return lib_fd;
}

// Check for vDSO binary in kernel directory (/lib/modules/<version>/vdso),
// rewrite the given lib_name string if found.
// Otherwise copy vDSO memory in coredump to temporal file generated by tmpfile().
// Returns FD for vDSO (should be closed by caller), or -1 on error.
static int handle_vdso(struct ps_prochandle* ph, char* lib_name, size_t lib_name_len) {
  int lib_fd;

  // Check vDSO binary first (for referring debuginfo if possible).
  lib_fd = handle_vdso_internal(ph, "vdso64.so", lib_name, lib_name_len);
  if (lib_fd == -1) {
    // Try again with vdso.so
    lib_fd = handle_vdso_internal(ph, "vdso.so", lib_name, lib_name_len);
  }
  if (lib_fd == -1) {
    // Copy vDSO memory segment from core to temporal memory
    // if vDSO binary is not available.
    FILE* tmpf = tmpfile();
    if (tmpf == NULL) {
      print_debug("can't create tmpfile for vDSO (%d)\n", errno);
      lib_fd = -1;
    } else {
      lib_fd = fileno(tmpf);
      off_t ofs = ph->core->vdso_offset;
      if (sendfile(lib_fd, ph->core->core_fd, &ofs, ph->core->vdso_size) == -1) {
        print_debug("can't copy vDSO (%d)\n", errno);
        fclose(tmpf);
        lib_fd = -1;
      }
    }
  }

  return lib_fd;
}

// read shared library info from runtime linker's data structures.
// This work is done by librtlb_db in Solaris
static bool read_shared_lib_info(struct ps_prochandle* ph) {
  uintptr_t addr = ph->core->dynamic_addr;
  uintptr_t debug_base;
  uintptr_t first_link_map_addr;
  uintptr_t ld_base_addr;
  uintptr_t link_map_addr;
  uintptr_t lib_base_diff;
  uintptr_t lib_base;
  uintptr_t lib_name_addr;
  char lib_name[BUF_SIZE];
  ELF_DYN dyn;
  ELF_EHDR elf_ehdr;
  int lib_fd;

  // _DYNAMIC has information of the form
  //         [tag] [data] [tag] [data] .....
  // Both tag and data are pointer sized.
  // We look for dynamic info with DT_DEBUG. This has shared object info.
  // refer to struct r_debug in link.h

  dyn.d_tag = DT_NULL;
  while (dyn.d_tag != DT_DEBUG) {
    if (ps_pdread(ph, (psaddr_t) addr, &dyn, sizeof(ELF_DYN)) != PS_OK) {
      print_error("can't read debug info from _DYNAMIC\n");
      return false;
    }
    addr += sizeof(ELF_DYN);
  }

  // we have got Dyn entry with DT_DEBUG
  debug_base = dyn.d_un.d_ptr;
  // at debug_base we have struct r_debug. This has first link map in r_map field
  if (ps_pdread(ph, (psaddr_t) debug_base + FIRST_LINK_MAP_OFFSET,
                 &first_link_map_addr, sizeof(uintptr_t)) != PS_OK) {
    print_error("can't read first link map address\n");
    return false;
  }

  // read ld_base address from struct r_debug
  if (ps_pdread(ph, (psaddr_t) debug_base + LD_BASE_OFFSET, &ld_base_addr,
                 sizeof(uintptr_t)) != PS_OK) {
    print_error("can't read ld base address\n");
    return false;
  }
  ph->core->ld_base_addr = ld_base_addr;

  print_debug("interpreter base address is 0x%lx\n", ld_base_addr);

  // now read segments from interp (i.e ld.so or ld-linux.so or ld-elf.so)
  if (read_interp_segments(ph) != true) {
      print_error("failed to read interp segments\n");
      return false;
  }

  // after adding interpreter (ld.so) mappings sort again
  if (sort_map_array(ph) != true) {
    print_error("failed to sort segment map array\n");
    return false;
  }

   print_debug("first link map is at 0x%lx\n", first_link_map_addr);

   link_map_addr = first_link_map_addr;
   while (link_map_addr != 0) {
      // read library base address of the .so. Note that even though <sys/link.h> calls
      // link_map->l_addr as "base address",  this is * not * really base virtual
      // address of the shared object. This is actually the difference b/w the virtual
      // address mentioned in shared object and the actual virtual base where runtime
      // linker loaded it. We use "base diff" in read_lib_segments call below.

      if (ps_pdread(ph, (psaddr_t) link_map_addr + LINK_MAP_ADDR_OFFSET,
                   &lib_base_diff, sizeof(uintptr_t)) != PS_OK) {
         print_error("can't read shared object base address diff\n");
         return false;
      }

      // read address of the name
      if (ps_pdread(ph, (psaddr_t) link_map_addr + LINK_MAP_NAME_OFFSET,
                    &lib_name_addr, sizeof(uintptr_t)) != PS_OK) {
         print_error("can't read address of shared object name\n");
         return false;
      }

      // read name of the shared object
      lib_name[0] = '\0';
      if (lib_name_addr != 0 &&
          read_string(ph, (uintptr_t) lib_name_addr, lib_name, sizeof(lib_name)) != true) {
         print_debug("can't read shared object name\n");
         // don't let failure to read the name stop opening the file.  If something is really wrong
         // it will fail later.
      }

      if (lib_name[0] != '\0') { // ignore empty lib names
         // We can use lib_base_diff to compare with vdso_addr
         // because base address of vDSO should be 0.
         if (lib_base_diff == ph->core->vdso_addr) {
           lib_fd = handle_vdso(ph, lib_name, sizeof(lib_name));
         } else {
           lib_fd = pathmap_open(lib_name);
         }

         if (lib_fd < 0) {
            print_debug("can't open shared object %s\n", lib_name);
            // continue with other libraries...
         } else {
            if (read_elf_header(lib_fd, &elf_ehdr)) {
               if (lib_base_diff == ZERO_LOAD_ADDRESS ) {
                 lib_base_diff = calc_prelinked_load_address(ph, lib_fd, &elf_ehdr, link_map_addr);
                 if (lib_base_diff == INVALID_LOAD_ADDRESS) {
                   close(lib_fd);
                   print_error("failed to calculate load address\n");
                   return false;
                 }
               }

               lib_base = lib_base_diff + find_base_address(lib_fd, &elf_ehdr);
               print_debug("reading library %s @ 0x%lx [ 0x%lx ]\n",
                           lib_name, lib_base, lib_base_diff);
               // while adding library mappings we need to use "base difference".
               if (! read_lib_segments(ph, lib_fd, &elf_ehdr, lib_base_diff)) {
                  print_error("can't read shared object's segments\n");
                  close(lib_fd);
                  return false;
               }
               add_lib_info_fd(ph, lib_name, lib_fd, lib_base);
               // Map info is added for the library (lib_name) so
               // we need to re-sort it before calling the p_pdread.
               if (sort_map_array(ph) != true) {
                  print_error("failed to sort segment map array\n");
                  return false;
               }
            } else {
               print_debug("can't read ELF header for shared object %s\n", lib_name);
               close(lib_fd);
               // continue with other libraries...
            }
         }
      }

    // read next link_map address
    if (ps_pdread(ph, (psaddr_t) link_map_addr + LINK_MAP_NEXT_OFFSET,
                   &link_map_addr, sizeof(uintptr_t)) != PS_OK) {
      print_error("can't read next link in link_map\n");
      return false;
    }
  }

  return true;
}

#ifdef __ANDROID__
static bool parse_tombstone(struct ps_prochandle* ph) {
    FILE* fp = fdopen(dup(ph->core->core_fd), "r");
    if (!fp) {
        print_error("parse_tombstone: failed to fdopen core file\n");
        return false;
    }

    char line[1024];
    int current_tid = 0;
    struct user_regs_struct current_regs;
    int regs_filled = 0;

    memset(&current_regs, 0, sizeof(current_regs));

    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';

        if (strncmp(line, "---", 3) == 0) {
            if (current_tid != 0 && regs_filled) {
                thread_info* thr = add_thread_info(ph, current_tid);
                if (thr) {
                    memcpy(&thr->regs, &current_regs, sizeof(current_regs));
                }
            }
            current_tid = 0;
            regs_filled = 0;
            continue;
        }

        if (sscanf(line, "pid: %*d, tid: %d", &current_tid) == 1) {
            continue;
        }

#if defined(__aarch64__)
        if (strncmp(line, "      x0 ", 9) == 0) {
            sscanf(line, "      x0 %llx  x1 %llx  x2 %llx  x3 %llx",
                   &current_regs.regs[0], &current_regs.regs[1],
                   &current_regs.regs[2], &current_regs.regs[3]);
            regs_filled = 1;
        } else if (strncmp(line, "      x4 ", 9) == 0) {
            sscanf(line, "      x4 %llx  x5 %llx  x6 %llx  x7 %llx",
                   &current_regs.regs[4], &current_regs.regs[5],
                   &current_regs.regs[6], &current_regs.regs[7]);
        } else if (strncmp(line, "      x8 ", 9) == 0) {
            sscanf(line, "      x8 %llx  x9 %llx  x10 %llx  x11 %llx",
                   &current_regs.regs[8], &current_regs.regs[9],
                   &current_regs.regs[10], &current_regs.regs[11]);
        } else if (strncmp(line, "      x12 ", 10) == 0) {
            sscanf(line, "      x12 %llx  x13 %llx  x14 %llx  x15 %llx",
                   &current_regs.regs[12], &current_regs.regs[13],
                   &current_regs.regs[14], &current_regs.regs[15]);
        } else if (strncmp(line, "      x16 ", 10) == 0) {
            sscanf(line, "      x16 %llx  x17 %llx  x18 %llx  x19 %llx",
                   &current_regs.regs[16], &current_regs.regs[17],
                   &current_regs.regs[18], &current_regs.regs[19]);
        } else if (strncmp(line, "      x20 ", 10) == 0) {
            sscanf(line, "      x20 %llx  x21 %llx  x22 %llx  x23 %llx",
                   &current_regs.regs[20], &current_regs.regs[21],
                   &current_regs.regs[22], &current_regs.regs[23]);
        } else if (strncmp(line, "      x24 ", 10) == 0) {
            sscanf(line, "      x24 %llx  x25 %llx  x26 %llx  x27 %llx",
                   &current_regs.regs[24], &current_regs.regs[25],
                   &current_regs.regs[26], &current_regs.regs[27]);
        } else if (strncmp(line, "      x28 ", 10) == 0) {
            sscanf(line, "      x28 %llx  x29 %llx  x30 %llx  sp %llx",
                   &current_regs.regs[28], &current_regs.regs[29],
                   &current_regs.regs[30], &current_regs.sp);
        } else if (strncmp(line, "      pc ", 9) == 0) {
            sscanf(line, "      pc %llx", &current_regs.pc);
        } else if (strncmp(line, "      pstate ", 13) == 0) {
            sscanf(line, "      pstate %llx", &current_regs.pstate);
        }

#elif defined(__arm__)
        if (strncmp(line, "      r0 ", 9) == 0) {
            sscanf(line, "      r0 %lx  r1 %lx  r2 %lx  r3 %lx",
                   &current_regs.uregs[0], &current_regs.uregs[1],
                   &current_regs.uregs[2], &current_regs.uregs[3]);
            regs_filled = 1;
        } else if (strncmp(line, "      r4 ", 9) == 0) {
            sscanf(line, "      r4 %lx  r5 %lx  r6 %lx  r7 %lx",
                   &current_regs.uregs[4], &current_regs.uregs[5],
                   &current_regs.uregs[6], &current_regs.uregs[7]);
        } else if (strncmp(line, "      r8 ", 9) == 0) {
            sscanf(line, "      r8 %lx  r9 %lx  r10 %lx  r11 %lx",
                   &current_regs.uregs[8], &current_regs.uregs[9],
                   &current_regs.uregs[10], &current_regs.uregs[11]);
        } else if (strncmp(line, "      ip ", 9) == 0) {
            unsigned long ip, sp, lr, pc;
            sscanf(line, "      ip %lx  sp %lx  lr %lx  pc %lx",
                   &ip, &sp, &lr, &pc);
            current_regs.uregs[12] = ip;  // IP (r12)
            current_regs.uregs[13] = sp;  // SP (r13)
            current_regs.uregs[14] = lr;  // LR (r14)
            current_regs.uregs[15] = pc;  // PC (r15)
        } else if (strncmp(line, "      cpsr ", 11) == 0) {
            sscanf(line, "      cpsr %lx", &current_regs.uregs[16]);
        }

#elif defined(__x86_64__)
        if (strncmp(line, "    rax ", 8) == 0) {
            sscanf(line, "    rax %llx  rbx %llx  rcx %llx  rdx %llx",
                   &current_regs.rax, &current_regs.rbx,
                   &current_regs.rcx, &current_regs.rdx);
            regs_filled = 1;
        } else if (strncmp(line, "    rsi ", 8) == 0) {
            sscanf(line, "    rsi %llx  rdi %llx  rbp %llx  rsp %llx",
                   &current_regs.rsi, &current_regs.rdi,
                   &current_regs.rbp, &current_regs.rsp);
        } else if (strncmp(line, "     r8 ", 8) == 0) {
            sscanf(line, "     r8 %llx   r9 %llx  r10 %llx  r11 %llx",
                   &current_regs.r8, &current_regs.r9,
                   &current_regs.r10, &current_regs.r11);
        } else if (strncmp(line, "    r12 ", 8) == 0) {
            sscanf(line, "    r12 %llx  r13 %llx  r14 %llx  r15 %llx",
                   &current_regs.r12, &current_regs.r13,
                   &current_regs.r14, &current_regs.r15);
        } else if (strncmp(line, "    rip ", 8) == 0) {
            sscanf(line, "    rip %llx  eflags %llx",
                   &current_regs.rip, &current_regs.eflags);
        } else if (strncmp(line, "    cs ", 7) == 0) {
            sscanf(line, "    cs %llx  ss %llx  ds %llx  es %llx  fs %llx  gs %llx",
                   &current_regs.cs, &current_regs.ss,
                   &current_regs.ds, &current_regs.es,
                   &current_regs.fs, &current_regs.gs);
        }

#elif defined(__i386__)
        if (strncmp(line, "    eax ", 8) == 0) {
            sscanf(line, "    eax %lx  ebx %lx  ecx %lx  edx %lx",
                   &current_regs.eax, &current_regs.ebx,
                   &current_regs.ecx, &current_regs.edx);
            regs_filled = 1;
        } else if (strncmp(line, "    esi ", 8) == 0) {
            sscanf(line, "    esi %lx  edi %lx  ebp %lx  esp %lx",
                   &current_regs.esi, &current_regs.edi,
                   &current_regs.ebp, &current_regs.esp);
        } else if (strncmp(line, "    eip ", 8) == 0) {
            sscanf(line, "    eip %lx  eflags %lx  xcs %lx  xss %lx",
                   &current_regs.eip, &current_regs.eflags,
                   &current_regs.xcs, &current_regs.xss);
        }

#elif defined(__riscv) && (__riscv_xlen == 64)
        // RISC-V 64-bit support
        if (strncmp(line, "      ra ", 9) == 0) {
            unsigned long long ra, sp, gp, tp;
            sscanf(line, "      ra %llx  sp %llx  gp %llx  tp %llx",
                   &ra, &sp, &gp, &tp);
            current_regs.ra = ra;
            current_regs.sp = sp;
            current_regs.gp = gp;
            current_regs.tp = tp;
            regs_filled = 1;
        } else if (strncmp(line, "      t0 ", 9) == 0) {
            unsigned long long t0, t1, t2, fp;
            sscanf(line, "      t0 %llx  t1 %llx  t2 %llx  fp %llx",
                   &t0, &t1, &t2, &fp);
            current_regs.t0 = t0;
            current_regs.t1 = t1;
            current_regs.t2 = t2;
            current_regs.s0 = fp;   // fp = s0
        } else if (strncmp(line, "      s1 ", 9) == 0) {
            unsigned long long s1, a0, a1, a2;
            sscanf(line, "      s1 %llx  a0 %llx  a1 %llx  a2 %llx",
                   &s1, &a0, &a1, &a2);
            current_regs.s1 = s1;
            current_regs.a0 = a0;
            current_regs.a1 = a1;
            current_regs.a2 = a2;
        } else if (strncmp(line, "      a3 ", 9) == 0) {
            unsigned long long a3, a4, a5, a6;
            sscanf(line, "      a3 %llx  a4 %llx  a5 %llx  a6 %llx",
                   &a3, &a4, &a5, &a6);
            current_regs.a3 = a3;
            current_regs.a4 = a4;
            current_regs.a5 = a5;
            current_regs.a6 = a6;
        } else if (strncmp(line, "      a7 ", 9) == 0) {
            unsigned long long a7, s2, s3, s4;
            sscanf(line, "      a7 %llx  s2 %llx  s3 %llx  s4 %llx",
                   &a7, &s2, &s3, &s4);
            current_regs.a7 = a7;
            current_regs.s2 = s2;
            current_regs.s3 = s3;
            current_regs.s4 = s4;
        } else if (strncmp(line, "      s5 ", 9) == 0) {
            unsigned long long s5, s6, s7, s8;
            sscanf(line, "      s5 %llx  s6 %llx  s7 %llx  s8 %llx",
                   &s5, &s6, &s7, &s8);
            current_regs.s5 = s5;
            current_regs.s6 = s6;
            current_regs.s7 = s7;
            current_regs.s8 = s8;
        } else if (strncmp(line, "      s9 ", 9) == 0) {
            unsigned long long s9, s10, s11, t3;
            sscanf(line, "      s9 %llx  s10 %llx  s11 %llx  t3 %llx",
                   &s9, &s10, &s11, &t3);
            current_regs.s9 = s9;
            current_regs.s10 = s10;
            current_regs.s11 = s11;
            current_regs.t3 = t3;
        } else if (strncmp(line, "      t4 ", 9) == 0) {
            unsigned long long t4, t5, t6, pc;
            sscanf(line, "      t4 %llx  t5 %llx  t6 %llx  pc %llx",
                   &t4, &t5, &t6, &pc);
            current_regs.t4 = t4;
            current_regs.t5 = t5;
            current_regs.t6 = t6;
            current_regs.pc = pc;
        }
#endif // Architecture selection
    }

    // Save the last thread info
    if (current_tid != 0 && regs_filled) {
        thread_info* thr = add_thread_info(ph, current_tid);
        if (thr) {
            memcpy(&thr->regs, &current_regs, sizeof(current_regs));
        }
    }

    fclose(fp);

    // For tombstone files, we don't have memory mappings from PT_LOAD segments
    // So we need to create a minimal mapping structure to make the debugger work
    ph->core->num_maps = 0;
    ph->core->maps = NULL;
    ph->core->map_array = NULL;

    // Add a dummy mapping for the whole address space to allow memory reads
    // This is a simplification - in reality you'd need to parse /proc/pid/maps
    // from the tombstone or have the mappings embedded in the tombstone file
    if (ph->threads != NULL) {
        // Create a single mapping covering the entire address space
        // This is not accurate but allows basic register and stack inspection
        map_info* map = (map_info*)calloc(1, sizeof(map_info));
        if (map) {
            map->vaddr = 0x1000;  // Skip NULL page
            map->memsz = 0x7fffffffffff;  // Large enough to cover typical address space
            map->fd = ph->core->core_fd;
            map->offset = 0;
            map->flags = PF_R | PF_W | PF_X;
            
            // Add to map list
            map->next = ph->core->maps;
            ph->core->maps = map;
            ph->core->num_maps++;
            
            // Create map array for binary search
            sort_map_array(ph);
        }
    }

    return (ph->threads != NULL);
}
#endif // __ANDROID__

// the one and only one exposed stuff from this file
JNIEXPORT struct ps_prochandle* JNICALL
Pgrab_core(const char* exec_file, const char* core_file) {
  ELF_EHDR core_ehdr;
  ELF_EHDR exec_ehdr;

  struct ps_prochandle* ph = (struct ps_prochandle*) calloc(1, sizeof(struct ps_prochandle));
  if (ph == NULL) {
    print_error("can't allocate ps_prochandle\n");
    return NULL;
  }

  if ((ph->core = (struct core_data*) calloc(1, sizeof(struct core_data))) == NULL) {
    free(ph);
    print_error("can't allocate ps_prochandle\n");
    return NULL;
  }

  // initialize ph
  ph->ops = &core_ops;
  ph->core->core_fd   = -1;
  ph->core->exec_fd   = -1;
  ph->core->interp_fd = -1;

  // open the core file
  if ((ph->core->core_fd = open(core_file, O_RDONLY)) < 0) {
    print_error("can't open core file: %s\n", strerror(errno));
    goto err;
  }
  
#ifdef __ANDROID__
  if (!parse_tombstone(ph)) {
    print_error("failed to parse tombstone file (or not a tombstone)\n");
    goto err;
  }
  return ph;
#endif

  // read core file ELF header
  if (read_elf_header(ph->core->core_fd, &core_ehdr) != true || core_ehdr.e_type != ET_CORE) {
    print_error("core file is not a valid ELF ET_CORE file\n");
    goto err;
  }

  if ((ph->core->exec_fd = open(exec_file, O_RDONLY)) < 0) {
    print_error("can't open executable file: %s\n", strerror(errno));
    goto err;
  }

  if (read_elf_header(ph->core->exec_fd, &exec_ehdr) != true ||
      ((exec_ehdr.e_type != ET_EXEC) && (exec_ehdr.e_type != ET_DYN))) {
    print_error("executable file is not a valid ELF file\n");
    goto err;
  }

  // process core file segments
  if (read_core_segments(ph, &core_ehdr) != true) {
    print_error("failed to read core segments\n");
    goto err;
  }

  // process exec file segments
  uintptr_t exec_base_addr = read_exec_segments(ph, &exec_ehdr);
  if (exec_base_addr == 0L) {
    print_error("failed to read exec segments\n");
    goto err;
  }
  print_debug("exec_base_addr = 0x%lx\n", exec_base_addr);
  if (add_lib_info_fd(ph, exec_file, ph->core->exec_fd, exec_base_addr) == NULL) {
    print_error("failed to add lib info\n");
    goto err;
  }

  // allocate and sort maps into map_array, we need to do this
  // here because read_shared_lib_info needs to read from debuggee
  // address space
  if (sort_map_array(ph) != true) {
    print_error("failed to sort segment map array\n");
    goto err;
  }

  if (read_shared_lib_info(ph) != true) {
    print_error("failed to read libraries\n");
    goto err;
  }

  // sort again because we have added more mappings from shared objects
  if (sort_map_array(ph) != true) {
    print_error("failed to sort segment map array\n");
    goto err;
  }

  if (init_classsharing_workaround(ph) != true) {
    print_error("failed to workaround class sharing\n");
    goto err;
  }

  return ph;

err:
  Prelease(ph);
  return NULL;
}
