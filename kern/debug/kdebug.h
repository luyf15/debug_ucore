#ifndef __KERN_DEBUG_KDEBUG_H__
#define __KERN_DEBUG_KDEBUG_H__

#include <defs.h>

void print_kerninfo(void);
void print_stackframe(void);
void print_debuginfo(uintptr_t eip);

#define set_hardwarebp(addr, no, mask)\
    asm __volatile__(\
        "movl %0,%%eax \n"\
        "movl %%eax,%%dr%c[Index] \n"\
        "movl %1,%%eax \n"\
        "movl %%eax,%%dr7"\
        ::"r"(addr),"r"(mask),[Index]"i"(no)\
        :"eax");    \


#endif /* !__KERN_DEBUG_KDEBUG_H__ */

