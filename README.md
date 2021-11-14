# Debug UCore(JOS)

Since Ucore initialized interrupt/exception handlers, it's possible to dive deep into x86 exception mechanism and OS exception handling implemention. 

## Definition

[Exceptions and Interrupts Vector](https://www.notion.so/804eea0869be4bc692b42c21f58e68e2)

### Exception Classifications

1. **Faults** — A fault is an exception that can generally be corrected and that, once corrected, allows the program to be restarted with no loss of continuity. When a fault is reported, **the processor restores the machine state to the state prior to the beginning of execution of the faulting instruction**. The return address (saved contents of the CS and EIP registers) for the fault handler **points to the faulting instruction, rather than to the instruction following the faulting instruction**.
2. **Traps** — A trap is an exception that is reported **immediately following the execution of the trapping instruction**. Traps allow execution of a program or task to be continued without loss of program continuity. The return address for the trap handler **points to the instruction to be executed after the trapping instruction**.
3. **Aborts** — An abort is an exception that **does not always report the precise location of the instruction causing the exception and does not allow a restart of the program or task that caused the exception**. Aborts are used to report severe errors, such as hardware errors and inconsistent or illegal values in system tables.

### Debug Condition/Breakpoint

1. **Hardware breakpoint**: based on debug registers(DRn:0-7). There are three types of hard-bp: **instruction(execution) breakpoint**, **data memory(access) breakpoint** and **I/O(access) breakpoint (and general detect exception)**. Hardware breakpoint generates a #DB exception(INT 1).
2. **Software breakpoint**: based on instruction int 3(0xcc/0xcd,0x03). The first byte of breakpoint address will be replaced with 0xcc, so a #BP exception can be captured by OS/Debugger/EH when $PC points to breakpoint.
**Attention: #BP is a trap, so $PC automaticly points to the instruction following exception. Windows makes $PC decreased so debugger can execute target instruction again.**
3. **Single-Step**: based E/RFLAGS.TF bit. The processor generates a single-step debug exception **if (while an instruction is being executed) it detects that the TF flag in the EFLAGS register is set**. The exception is generated after the instruction is executed(trap-class). **The processor will not generate this exception after the instruction that sets the TF flag.** The processor clears the TF flag before calling the exception handler .The external interrupt handler does not run in single-step mode. To single step an interrupt handler, single step an INT n instruction that calls the interrupt handler.

#DB exception can be generated in various conditions. Here is a list.

[INT1 behavior](https://www.notion.so/89b1aa3a934947cb82666a441ea845fe)

# First: Initialize IDT and handler

The exception handler is defined in kern/trap/*. While OS is bootstrapping, *idt_init()* does the initialization.

```c
//trap.c
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

//trap.h
#define SETGATE(gate, istrap, sel, off, dpl) {            \
    (gate).gd_off_15_0 = (uint32_t)(off) & 0xffff;        \
    (gate).gd_ss = (sel);                                \
    (gate).gd_args = 0;                                    \
    (gate).gd_rsv1 = 0;                                    \
    (gate).gd_type = (istrap) ? STS_TG32 : STS_IG32;    \
    (gate).gd_s = 0;                                    \
    (gate).gd_dpl = (dpl);                                \
    (gate).gd_p = 1;                                    \
    (gate).gd_off_31_16 = (uint32_t)(off) >> 16;        \
}

//vector.S
.text
.globl __alltraps
.globl vector0
vector0:
  pushl $0
  pushl $0
  jmp __alltraps
...
(vectorn)
```

When exception/interrupt occurs, IDT will cause CPU jmp to vectorn, then goes to __alltraps. In __alltraps, OS restores the interrupted context and runs corresponding handler.

```c
//trapentry.S
.text
.globl __alltraps
__alltraps:
    # push registers to build a trap frame
    # therefore make the stack look like a struct trapframe
    pushl %ds
    pushl %es
    pushl %fs
    pushl %gs
    pushal

    # load GD_KDATA into %ds and %es to set up data segments for kernel
    movl $GD_KDATA, %eax
    movw %ax, %ds
    movw %ax, %es

    # push %esp to pass a pointer to the trapframe as an argument to trap()
    pushl %esp

    # call trap(tf), where tf=%esp
    call trap

    # pop the pushed stack pointer
    popl %esp

//trap.c
void
trap(struct trapframe *tf) {
    // dispatch based on what type of trap occurred
    trap_dispatch(tf);
}

static void
trap_dispatch(struct trapframe *tf) {
    char c;
    uint32_t count;
    bool tf_set=0;
    switch (tf->tf_trapno) {
    case IRQ_OFFSET + IRQ_TIMER:
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
        ...
        break;
		...
```

 When an external interrupt or internal interrupt or exception occurs, *trap_dispatch* is the true handler. So, if we need to change OS's exception/interrupt behavior, modify the function *trap_dispatch*. 

# Second: Self-Defined Interrupt/Trap

Let's define an interrupt which can cause privilege change. Why an interrupt not a trap? **The biggest diffrence between them is that when getting in an interrupt gate, CPU will disable interrupt(IF=0) firstly, while a trap gate will remain IF=1.**  (Nested Interrupt is not recommended, but a syscall may need external interrupts for their functions)

```c
//trap.h
#define T_SWITCH_TOU                120    // user/kernel switch
#define T_SWITCH_TOK                121    // user/kernel switch

//trap.c
static void
trap_dispatch(struct trapframe *tf) {
...
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
...
```

We can simply modify the values in *trapframe*(restored context) : when *trap* returns, CPU states(context) can switch to our expected values. In our example, T_SWITCH_TOU will change CS from 0x08 to 0x1b, DS, SS, ES from 0x10 to 0x23, which means the current program switched to ring3. (T_SWITCH_TOK on the contrary) 

### Result:

1. before the *switch_to_user* function: 
    
    ![Untitled](Debug%20UCore(JOS)%20b7d278a3e60c43998b59c43bf094ba85/Untitled.png)
    
    CS=0x8, DS=SS=ES=0x10: ring0
    
2. after *switch_to_user*, before *switch_to_kernel*
    
    ![Untitled](Debug%20UCore(JOS)%20b7d278a3e60c43998b59c43bf094ba85/Untitled%201.png)
    
    CS=0x1B, DS=SS=ES=0x23: ring3. Besides, we can see that the trapno=0x78 exception caused the privilege change.
    
3. after *switch_to_kernel*
    
    ![Untitled](Debug%20UCore(JOS)%20b7d278a3e60c43998b59c43bf094ba85/Untitled%202.png)
    
    0x79 trap exception made CPU back to ring0.
    

# Third: Syscall Prototype

x86-32 architecture provided  three types of IDT gate: interrupt gate, trap gate, task gate. As mentioned above, entering trap gate will remain EFLAGS.IF bit set, while interrupt gate will disable nested interrupt by clear that bit. We create a system call named *sleep*,which will wait *n* seconds(**from timer interrupt**) to print a message on console. Syscall need a trap gate to use external IO(interrupt), setting DPL=3 to allow ring3 access.

```c
//trap.h
#define USER_SLEEP                  122

//trap.c
size_t time = 0;

static uint32_t
sleep(uint32_t count) {
    //cprintf("test_para=%d\n",count);
    while (time < count);
    
    cprintf("sleep end: %d\n", time);
    time = 0;
    return 1;
}

void
idt_init(void) {
	...
	//trap gate,dpl=3
	SETGATE(idt[USER_SLEEP], 1, GD_KTEXT, __vectors[USER_SLEEP], DPL_USER);
	...
}

static void
trap_dispatch(struct trapframe *tf) {
    char c;
    uint32_t count;
    switch (tf->tf_trapno) {
    case IRQ_OFFSET + IRQ_TIMER:
        if (ticks % TICK_NUM == 0) {
            print_ticks();
            time ++;
        }
        break;
		...
		case USER_SLEEP:
	        //intr_enable();
	        count = *(uint32_t *)(tf->tf_esp);
	        tf->tf_regs.reg_eax = sleep(count);
	...
}

//init.c
static void
lab1_switch_test(void) {
	...
	lab1_switch_to_user();
	if (user_sleep(5))cprintf("User syscall sleep succeeded!\n");
	...
```

Result: 

![Untitled](Debug%20UCore(JOS)%20b7d278a3e60c43998b59c43bf094ba85/Untitled%203.png)

# Fourth: Debug and Breakpoints in kernel

When we debug a ring3 program, OS will make debugger host and handle exceptions, so that we can use breakpoints and trace the execution. But, when our position is in OS, exception handler in kernel is the first. as mentioned above, breakpoint and debug are treated as certain exception(int 1/3). OS exception behaviors vary based on our implementation. In *trap_dispatch* function, we handle various exceptions by trapno in  a switch-case block. 

```c
//trap.c
...

static void
trap_dispatch(struct trapframe *tf) {
	switch (tf->tf_trapno) {
		...
		case 0xd:   //#GP
        if (tf->tf_cs & 3)
            cprintf("GP!!trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
        SETGATE(idt[0x3], 0, GD_KTEXT, __vectors[0x3], DPL_USER);
        if (*(uint8_t *)tf->tf_eip == 0xcc)
            tf->tf_eip += 1;
        else if(*(uint8_t *)tf->tf_eip == 0xcd) 
            tf->tf_eip += 2;
        break;
    case 0x1:    //TF; hardware breakpoint;...(#DB)
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
    case 0x0:     //divided by 0 error(#DE)
        print_trapframe(tf);
        set_hardwarebp(tf->tf_eip + 1,0,0x403)
        //tf->tf_eflags |= 0x100;
        tf->tf_eip += 1;
        once = 1;
        break;
    case 0x3:      //breakpoint(#BP)
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
...

//kdebug.h
#define set_hardwarebp(addr, no, mask)\
    asm __volatile__(\
        "movl %0,%%eax \n"\
        "movl %%eax,%%dr%c[Index] \n"\
        "movl %1,%%eax \n"\
        "movl %%eax,%%dr7"\
        ::"r"(addr),"r"(mask),[Index]"i"(no)\
        :"eax");    \

#define user_int(no) \
    asm volatile (\
	    "int %0 \n"\
	    :: "i"(no));
```

int 1, int 3, #GP, #DE are processed in *trap_dispatch.* To invoke #DB correctly, we try to set TF bit(SET_TF exception) or set a hardware breakpoint(set_hardwarebp MARCO)——**explicit int 0x1 will be treated as int 0x3**.

To see differences between different exceptions above, in *kern_init*, we invoke them by various calls.

```c
//init.c
void
kern_init(void){
		...
    set_hardwarebp(0x100252,0,0x403)  //0x100252 <user_sleep>: 
		...
    lab1_switch_test();

    /* do nothing */
    while (1);
}

static void
lab1_switch_test(void) {
    lab1_print_cur_status();
    cprintf("+++ switch to  user  mode +++\n");
    lab1_switch_to_user();
    user_int(3)
    user_int(3)
    if (user_sleep(5))cprintf("User syscall sleep succeeded!\n");
    //cprintf("+++ switch to kernel mode +++\n");
    //lab1_switch_to_kernel();
    //lab1_print_cur_status();
}
```

In int 0x3, at start we can't grant int 0x3 to ring3, so actually #GP(0xd) raised. In 0xd branch, we change 0xd IDT descriptor's DPL to 3, resulting in the second int 3 will be caught normally.

![Untitled](Debug%20UCore(JOS)%20b7d278a3e60c43998b59c43bf094ba85/Untitled%204.png)

![Untitled](Debug%20UCore(JOS)%20b7d278a3e60c43998b59c43bf094ba85/Untitled%205.png)

`We can know that #GP is a fault while #BP is a trap.`

In int 0x1, we implement a single-step execution by controlling TF bit and hardware breakpoints(TF ⊕ hardware breakpoint). 

![Untitled](Debug%20UCore(JOS)%20b7d278a3e60c43998b59c43bf094ba85/Untitled%206.png)

![Untitled](Debug%20UCore(JOS)%20b7d278a3e60c43998b59c43bf094ba85/Untitled%207.png)

![Untitled](Debug%20UCore(JOS)%20b7d278a3e60c43998b59c43bf094ba85/Untitled%208.png)

`We can know that #DB from hardware breakpoints is a fault while TF-caused #DB is a trap.`

# Fifth: Attempt to jump over fault instructions

Since CPU would not execute the instruction which raise the fault when fault exception happened, we can get the linear address of target instruction. In trapframe, we can control the control flow when *iret(ss,esp,eflags,cs,eip)*. For example, #DE is a fault, what if we inc eip in the trapframe.

```c
//init.c
asm __volatile__(
            "movl %0,%%eax \n"
            "movl %%eax,%%edx \n"
            "xor %%eax,%%eax \n"
            "xor %%edx,%%edx \n"
            "div %%eax \n"
            "div %%edx \n"
            "movl %%ebx,%%eax"
            ::"i"(114)
            :"eax","edx"
        );

//trap.c
static void
trap_dispatch(struct trapframe *tf) {
case 0x0:
        print_trapframe(tf);
        set_hardwarebp(tf->tf_eip + 1,0,0x403)
        tf->tf_eip += 1;
        once = 1;
        break;

//kernel.asm
asm __volatile__(
  100083:	b8 72 00 00 00       	mov    $0x72,%eax
  100088:	89 c2                	mov    %eax,%edx
  10008a:	31 c0                	xor    %eax,%eax
  10008c:	31 d2                	xor    %edx,%edx
  10008e:	f7 f0                	div    %eax
  100090:	f7 f2                	div    %edx
  100092:	89 d8                	mov    %ebx,%eax
```

Result:

```c
**trapframe at 0x7b7c
  trap 0x00000000 Divide error
  eip  0x0010008e
  flag 0x00000246 PF,ZF,IF,IOPL=0**
trapframe at 0x7b7c
  trap 0x00000001 Debug
  eip  0x0010008f
  flag 0x00000246 PF,ZF,IF,IOPL=0
**trapframe at 0x7b7c
  trap 0x00000000 Divide error
  eip  0x0010008f
  flag 0x00000346 PF,ZF,TF,IF,IOPL=0**
trapframe at 0x7b7c
  trap 0x00000001 Debug
  eip  0x00100090
  flag 0x00000346 PF,ZF,TF,IF,IOPL=0
trapframe at 0x7b7c
  trap 0x00000001 Debug
  eip  0x00100090
  flag 0x00000246 PF,ZF,IF,IOPL=0
**trapframe at 0x7b7c
  trap 0x00000000 Divide error
  eip  0x00100090
  flag 0x00000346 PF,ZF,TF,IF,IOPL=0**
trapframe at 0x7b7c
  trap 0x00000001 Debug
  eip  0x00100091
  flag 0x00000346 PF,ZF,TF,IF,IOPL=0
trapframe at 0x7b7c
  trap 0x00000001 Debug
  eip  0x00100091
  flag 0x00000246 PF,ZF,IF,IOPL=0
...
```

It seems that OS skipped the two divided-by-0 instructions.

What if we make a more complex sequence?

```c
asm __volatile__(
            "movl %0,%%eax \n"
            "movl %%eax,%%edx \n"
            "xor %%eax,%%eax \n"
            "xor %%edx,%%edx \n"
            "div %%eax \n"
            "inc %%edx \n"
            "div %%eax \n"
            "movl %%ebx,%%eax"
            ::"i"(114)
            :"eax","edx"
        );
```

Result:

```c
trapframe at 0x7b7c
  trap 0x00000000 Divide error
  eip  0x0010008e
  flag 0x00000246 PF,ZF,IF,IOPL=0
trapframe at 0x7b7c
  trap 0x00000001 Debug
  eip  0x0010008f
  flag 0x00000246 PF,ZF,IF,IOPL=0
**trapframe at 0x7b7c
  trap 0x00000006 Invalid Opcode
  eip  0x0010008f
  flag 0x00000346 PF,ZF,TF,IF,IOPL=0**
kernel panic at kern/trap/trap.c:337:
    unexpected trap in kernel:0x00000006, Invalid Opcode
```

A #UD was raised. Therefore, to skip specific instruction in CISC need decoding instructions. If a part of instrucion is ignored, #UD is relatively OK because some undefined behaviors are far more dangerous.