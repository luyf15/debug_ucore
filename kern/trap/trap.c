#include <defs.h>
#include <mmu.h>
#include <memlayout.h>
#include <clock.h>
#include <trap.h>
#include <x86.h>
#include <stdio.h>
#include <assert.h>
#include <console.h>
#include <kdebug.h>
#include <string.h>
#include <intr.h>
#include <atomic.h>

#define TICK_NUM 100

static void print_ticks() {
    cprintf("%d ticks\n",TICK_NUM);
#ifdef DEBUG_GRADE
    cprintf("End of Test.\n");
    panic("EOT: kernel seems ok.");
#endif
}
size_t time = 0;
extern uintptr_t __vectors[];

static uint32_t
sleep(uint32_t count) {
    //cprintf("test_para=%d\n",count);
    while (time < count);
    
    cprintf("sleep end: %d\n", time);
    time = 0;
    return 1;
}

/* *
 * Interrupt descriptor table:
 *
 * Must be built at run time because shifted function addresses can't
 * be represented in relocation records.
 * */
static struct gatedesc idt[256] = {{0}};

static struct pseudodesc idt_pd = {sizeof(idt)-1, (uintptr_t)idt};

/* idt_init - initialize IDT to each of the entry points in kern/trap/vectors.S */
void
idt_init(void) {
     /* (1) All ISR's entry addrs are stored in __vectors[] (in kern/trap/vector.S which is produced by tools/vector.c)
      * (2) Use SETGATE macro to setup each item of IDT
      * (3) CPU know where is the IDT by 'idtr', which 'lidt' instruction can load idt's address into.
      */
    idt_pd.pd_base = (uintptr_t)idt;
    idt_pd.pd_lim = sizeof(idt) - 1;
    int i;
    for (i = 0; i < sizeof(idt) / sizeof(struct gatedesc); i ++) {
        SETGATE(idt[i], 0, GD_KTEXT, __vectors[i], DPL_KERNEL);
    }
	// set for switch from user to kernel
    SETGATE(idt[T_SWITCH_TOK], 0, GD_KTEXT, __vectors[T_SWITCH_TOK], DPL_USER);
    SETGATE(idt[SET_TF], 1, GD_KTEXT, __vectors[SET_TF], DPL_USER);
    SETGATE(idt[USER_SLEEP], 1, GD_KTEXT, __vectors[USER_SLEEP], DPL_USER);
	// load the IDT
    lidt(&idt_pd);
}

static const char *
trapname(int trapno) {
    static const char * const excnames[] = {
        "Divide error",
        "Debug",
        "Non-Maskable Interrupt",
        "Breakpoint",
        "Overflow",
        "BOUND Range Exceeded",
        "Invalid Opcode",
        "Device Not Available",
        "Double Fault",
        "Coprocessor Segment Overrun",
        "Invalid TSS",
        "Segment Not Present",
        "Stack Fault",
        "General Protection",
        "Page Fault",
        "(unknown trap)",
        "x87 FPU Floating-Point Error",
        "Alignment Check",
        "Machine-Check",
        "SIMD Floating-Point Exception"
    };
    static const char * const unitrap[] = {
        "switch from kernel to user",
        "switch from user to kernel",
        "user sleep"
        "set TF flag"
    };
    if (trapno < sizeof(excnames)/sizeof(const char * const)) {
        return excnames[trapno];
    }
    if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16) {
        return "Hardware Interrupt";
    }
    if (trapno >= T_SWITCH_TOU && trapno <= SET_TF) {
        return unitrap[trapno - T_SWITCH_TOU];
    }
    return "(unknown trap)";
}

/* trap_in_kernel - test if trap happened in kernel */
bool
trap_in_kernel(struct trapframe *tf) {
    return (tf->tf_cs == (uint16_t)KERNEL_CS);
}

static const char *IA32flags[] = {
    "CF", NULL, "PF", NULL, "AF", NULL, "ZF", "SF",
    "TF", "IF", "DF", "OF", NULL, NULL, "NT", NULL,
    "RF", "VM", "AC", "VIF", "VIP", "ID", NULL, NULL,
};

void
print_trapframe(struct trapframe *tf) {
    cprintf("trapframe at %p\n", tf);
    print_regs(&tf->tf_regs);
    cprintf("  ds   0x----%04x\n", tf->tf_ds);
    cprintf("  es   0x----%04x\n", tf->tf_es);
    cprintf("  fs   0x----%04x\n", tf->tf_fs);
    cprintf("  gs   0x----%04x\n", tf->tf_gs);
    cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
    cprintf("  err  0x%08x\n", tf->tf_err);
    cprintf("  eip  0x%08x\n", tf->tf_eip);
    cprintf("  cs   0x----%04x\n", tf->tf_cs);
    cprintf("  flag 0x%08x ", tf->tf_eflags);

    int i, j;
    for (i = 0, j = 1; i < sizeof(IA32flags) / sizeof(IA32flags[0]); i ++, j <<= 1) {
        if ((tf->tf_eflags & j) && IA32flags[i] != NULL) {
            cprintf("%s,", IA32flags[i]);
        }
    }
    cprintf("IOPL=%d\n", (tf->tf_eflags & FL_IOPL_MASK) >> 12);

    if (!trap_in_kernel(tf)) {
        cprintf("  esp  0x%08x\n", tf->tf_esp);
        cprintf("  ss   0x----%04x\n", tf->tf_ss);
    }
}

void
print_regs(struct pushregs *regs) {
    cprintf("  edi  0x%08x\n", regs->reg_edi);
    cprintf("  esi  0x%08x\n", regs->reg_esi);
    cprintf("  ebp  0x%08x\n", regs->reg_ebp);
    cprintf("  oesp 0x%08x\n", regs->reg_oesp);
    cprintf("  ebx  0x%08x\n", regs->reg_ebx);
    cprintf("  edx  0x%08x\n", regs->reg_edx);
    cprintf("  ecx  0x%08x\n", regs->reg_ecx);
    cprintf("  eax  0x%08x\n", regs->reg_eax);
}

/* temporary trapframe or pointer to trapframe */
struct trapframe switchk2u, *switchu2k;
uintptr_t once = 0,igneip = 0;

/* trap_dispatch - dispatch based on what type of trap occurred */
static void
trap_dispatch(struct trapframe *tf) {
    char c;
    uint32_t count;
    bool tf_set=0;
    switch (tf->tf_trapno) {
    case IRQ_OFFSET + IRQ_TIMER:
        /* LAB1 YOUR CODE : STEP 3 */
        /* handle the timer interrupt */
        /* (1) After a timer interrupt, you should record this event using a global variable (increase it), such as ticks in kern/driver/clock.c
         * (2) Every TICK_NUM cycle, you can print some info using a funciton, such as print_ticks().
         * (3) Too Simple? Yes, I think so!
         */
        ticks ++;
        if (ticks % TICK_NUM == 0) {
            print_ticks();
            time ++;
        }
        break;
    case IRQ_OFFSET + IRQ_COM1:
        c = cons_getc();
        cprintf("serial [%03d] %c\n", c, c);
        break;
    case IRQ_OFFSET + IRQ_KBD:
        c = cons_getc();
        cprintf("kbd [%03d] %c\n", c, c);
        if(c == 'U' || c == 'u' || c == '3'){
            if (tf->tf_cs != USER_CS) {
                tf->tf_cs = USER_CS;
                tf->tf_ds = tf->tf_es = tf->tf_ss = USER_DS;
                //may have no privilede change
                tf->tf_esp = (uint32_t)tf + sizeof(struct trapframe) - 8;
            
                // set eflags, make sure ucore can use io under user mode.
                // if CPL > IOPL, then cpu will generate a general protection.
                tf->tf_eflags |= FL_IOPL_MASK;
            
                // set temporary stack
                // then iret will jump to the right stack
            }
            else
                cprintf("Already in user mode!\n");
        }
        else if(c == 'K' || c == 'k' || c == '0'){
            if (tf->tf_cs != KERNEL_CS) {
                tf->tf_cs = KERNEL_CS;
                tf->tf_ds = tf->tf_es = KERNEL_DS;
                tf->tf_eflags &= ~FL_IOPL_MASK;
            }
            else
                cprintf("Already in kernel mode!\n");
        }
        break;
    //LAB1 CHALLENGE 1 : YOUR CODE you should modify below codes..
    #if 0
    case T_SWITCH_TOU:
        if (tf->tf_cs != USER_CS) {
            switchk2u = *tf;
            switchk2u.tf_cs = USER_CS;
            switchk2u.tf_ds = switchk2u.tf_es = switchk2u.tf_ss = USER_DS;
            switchk2u.tf_esp = (uint32_t)tf + sizeof(struct trapframe) - 8;
		
            // set eflags, make sure ucore can use io under user mode.
            // if CPL > IOPL, then cpu will generate a general protection.
            switchk2u.tf_eflags |= FL_IOPL_MASK;
		
            // set temporary stack
            // then iret will jump to the right stack
            *((uint32_t *)tf - 1) = (uint32_t)&switchk2u;
        }
        break;
    case T_SWITCH_TOK:
        if (tf->tf_cs != KERNEL_CS) {
            tf->tf_cs = KERNEL_CS;
            tf->tf_ds = tf->tf_es = KERNEL_DS;
            tf->tf_eflags &= ~FL_IOPL_MASK;
            switchu2k = (struct trapframe *)(tf->tf_esp - (sizeof(struct trapframe) - 8));
            memmove(switchu2k, tf, sizeof(struct trapframe) - 8);
            *((uint32_t *)tf - 1) = (uint32_t)switchu2k;
        }
        break;
    #endif
    case T_SWITCH_TOU:
        if (tf->tf_cs != USER_CS) {
            tf->tf_cs = USER_CS;
            tf->tf_ds = tf->tf_es = tf->tf_ss = USER_DS;
            tf->tf_esp = (uint32_t)tf + sizeof(struct trapframe) - 8;
		
            // set eflags, make sure ucore can use io under user mode.
            // if CPL > IOPL, then cpu will generate a general protection.
            tf->tf_eflags |= FL_IOPL_MASK;
		
            // set temporary stack
            // then iret will jump to the right stack

            print_trapframe(tf);
        }
        break;
    case T_SWITCH_TOK:
        if (tf->tf_cs != KERNEL_CS) {
            tf->tf_cs = KERNEL_CS;
            tf->tf_ds = tf->tf_es = KERNEL_DS;
            tf->tf_eflags &= ~FL_IOPL_MASK;

            print_trapframe(tf);
        }
        break;
    case IRQ_OFFSET + IRQ_IDE1:
    case IRQ_OFFSET + IRQ_IDE2:
        /* do nothing */
        break;
    case USER_SLEEP:
        //intr_enable();
        count = *(uint32_t *)(tf->tf_esp);
        tf->tf_regs.reg_eax = sleep(count);
        tf->tf_eflags &= ~0x100;
        //intr_disable();
        //*(uint32_t *)(tf->tf_esp - 4) = sleep(count);
        break;
    case 0xd:
        if (tf->tf_cs & 3)
            cprintf("GP!!trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
        SETGATE(idt[0x3], 0, GD_KTEXT, __vectors[0x3], DPL_USER);
        if (*(uint8_t *)tf->tf_eip == 0xcc)
            tf->tf_eip += 1;
        else if(*(uint8_t *)tf->tf_eip == 0xcd) 
            tf->tf_eip += 2;
        break;
    case 0x1:
        print_trapframe(tf);
        if (!test_bit(8,&tf->tf_eflags)){
            set_hardwarebp(tf->tf_eip,0,0x400)
            tf->tf_eflags |= 0x100;
            if (igneip){
                tf->tf_eip = igneip;
                igneip = 0;
            }
        }
        else{
            igneip = tf->tf_eip;
            if (once){
                tf->tf_eflags &= ~0x100;
                once = 0;
            }
        }
        break;
    case 0x0:
        print_trapframe(tf);
        set_hardwarebp(tf->tf_eip + 1,0,0x403)
        //tf->tf_eflags |= 0x100;
        tf->tf_eip += 1;
        once = 1;
        break;
    case 0x3:
        print_trapframe(tf);
        break;
    case SET_TF:
        if (!tf_set || !test_bit(8,&tf->tf_eflags)){
            tf->tf_eflags |= 0x100;
            tf_set = 1;
        }
        else if (tf_set || test_bit(8,&tf->tf_eflags)){
            tf->tf_eflags &= ~0x100;
            tf_set = 0;
        }
        break;
    default:
        // in kernel, it must be a mistake
        if ((tf->tf_cs & 3) == 0) {
            print_trapframe(tf);
            panic("unexpected trap in kernel:0x%08x, %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
        }
        else cprintf("unexpected trap in user:0x%08x, %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
    }
}

/* *
 * trap - handles or dispatches an exception/interrupt. if and when trap() returns,
 * the code in kern/trap/trapentry.S restores the old CPU state saved in the
 * trapframe and then uses the iret instruction to return from the exception.
 * */
void
trap(struct trapframe *tf) {
    // dispatch based on what type of trap occurred
    trap_dispatch(tf);
}

