/*********************************************************************
 *                SEGGER MICROCONTROLLER SYSTEME GmbH                 *
 *        Solutions for real time microcontroller applications        *
 **********************************************************************
 *                                                                    *
 *        (C) 2004-2009    SEGGER Microcontroller Systeme GmbH        *
 *                                                                    *
 *      Internet: www.segger.com    Support:  support@segger.com      *
 *                                                                    *
 **********************************************************************
 ----------------------------------------------------------------------
 File        : RTOSPlugin.c
 Purpose     : Extracts information about tasks from RTOS.

 Additional information:
 Eclipse based debuggers show information about threads.

 ---------------------------END-OF-HEADER------------------------------
*/

#include "RTOSPlugin.h"
#include "JLINKARM_Const.h"
#include <stdio.h>
#include <assert.h>

/*********************************************************************
 *
 *       Defines, fixed
 *
 **********************************************************************
 */

#ifdef WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

/*********************************************************************
 *
 *       Defines, configurable
 *
 **********************************************************************
 */

#define PLUGIN_VERSION             100

/*********************************************************************
 *
 *       Types, local
 *
 **********************************************************************
 */

#define LOG(fmt, ...) gdb_api->pfLogOutf("### %s: " fmt, __func__, ##__VA_ARGS__)
#define ERROR(fmt, ...) gdb_api->pfErrorOutf("### %s: " fmt, __func__, ##__VA_ARGS__)

struct os_task_stailq {
    U32 stqh_first;/* first element */
    U32 stqh_last;/* addr of last next element */
};

#define	STAILQ_FIRST(head)	((head)->stqh_first)

#define	STAILQ_NEXT(elm, field)	((elm)->field.stqe_next)

#define	STAILQ_ENTRY(type)						\
    struct {                                    \
        U32 stqe_next;	/* next element */      \
    }

#define	TAILQ_ENTRY(type)                                       \
    struct {                                                    \
        U32 tqe_next;	/* next element */                      \
        U32 tqe_prev;	/* address of previous next element */	\
    }

#define	SLIST_ENTRY(type)                       \
    struct {                                    \
        U32 sle_next;  /* next element */       \
    }

struct os_sanity_check;

struct os_sanity_check {
    U32 sc_checkin_last;
    U32 sc_checkin_itvl;
    U32 sc_func;
    U32 sc_arg;

    SLIST_ENTRY(U32) sc_next;
};

struct os_task {
    U32 t_stackptr;
    U32 t_stacktop;

    U16 t_stacksize;
    U8 t_taskid;
    U8 t_prio;

    U8 t_state;
    U8 t_flags;
    U8 t_lockcnt;
    U8 t_pad;

    U32 t_name;
    U32 t_func;
    U32 t_arg;

    U32 t_obj;

    struct os_sanity_check t_sanity_check;

    U32 t_next_wakeup;
    U32 t_run_time;
    U32 t_ctx_sw_cnt;

    /* Global list of all tasks, irrespective of run or sleep lists */
    STAILQ_ENTRY(U32) t_os_task_list;

    /* Used to chain task to either the run or sleep list */
    TAILQ_ENTRY(U32) t_os_list;

    /* Used to chain task to an object such as a semaphore or mutex */
    SLIST_ENTRY(U32) t_obj_list;
};

#define OS_TASK_MAX_NAME_LEN (32)

typedef struct {
    U32 id;
    U8 prio;
    char *name;
    const char *state_str;
    U32 addr;
} THREAD_DETAIL;

typedef struct {
    U8  data[0xD0];     // stack data, maximum possible stack size
    U32 pointer;        // stack pointer
    U32 threadid;       // thread ID
} STACK_MEM;

typedef struct {
    signed short   offset;
    unsigned short bits;
} STACK_REGS;

typedef struct _Stacking {
    U8 registers_size;
    I8 growth_direction;
    U8 output_registers;
    U32 (*stack_align_f) (const struct _Stacking *stacking, const U8 *stack_data, U32 stack_ptr);
    const STACK_REGS *register_offsets;
} STACKING;

/*********************************************************************
 *
 *       Static data
 *
 **********************************************************************
 */

static const GDB_API *gdb_api;

static STACK_MEM stack_mem;

static struct {
    const STACKING *stacking_info;
    U32 current_taskid;
    U8 task_count;
    U32 num_task_details;
    THREAD_DETAIL *task_details;
} mynewt_os;

static const STACK_REGS cortex_m_stack_offsets[] = {
    { 0x20, 32 },    // R0
    { 0x24, 32 },    // R1
    { 0x28, 32 },    // R2
    { 0x2C, 32 },    // R3
    { 0x00, 32 },    // R4
    { 0x04, 32 },    // R5
    { 0x08, 32 },    // R6
    { 0x0C, 32 },    // R7
    { 0x10, 32 },    // R8
    { 0x14, 32 },    // R9
    { 0x18, 32 },    // R10
    { 0x1C, 32 },    // R11
    { 0x30, 32 },    // R12
    { -2,   32 },    // SP
    { 0x34, 32 },    // LR
    { 0x38, 32 },    // PC
    { 0x3C, 32 },    // XPSR
    { -1,   32 },    // MSP
    { -1,   32 },    // PSP
    { -1,   32 },    // PRIMASK
    { -1,   32 },    // BASEPRI
    { -1,   32 },    // FAULTMASK
    { -1,   32 },    // CONTROL
};

static RTOS_SYMBOLS symbols[] = {
    { "g_task_id", 0, 0 },
    { "g_current_task", 0, 0 },
    { "g_os_task_list", 0, 0 },
    { NULL, 0, 0 } };

enum RTOS_Symbol_Values {
    g_task_id = 0,
    g_current_task,
    g_os_task_list,
};

static U32 cortex_m_stack_align(const STACKING *stacking, const U8 *stack_data,
                                U32 stack_ptr, size_t xpsr_offset) {
    const U32 ALIGN_NEEDED = (1 << 9);
    U32 xpsr;
    U32 new_stack_ptr;

    new_stack_ptr = stack_ptr - stacking->growth_direction *
        stacking->registers_size;
    xpsr = gdb_api->pfLoad32TE(&stack_data[xpsr_offset]);
    if ((xpsr & ALIGN_NEEDED) != 0) {
        LOG("XPSR(0x%08X) indicated stack alignment was necessary.\n", xpsr);
        new_stack_ptr -= (stacking->growth_direction * 4);
    }
    return new_stack_ptr;
}

static U32 cortex_m0_m4_stack_align(const STACKING *stacking,
                                 const U8 *stack_data, U32 stack_ptr) {
    return cortex_m_stack_align(stacking, stack_data, stack_ptr, 0x3C);
}

static const STACKING cortex_m_stacking = {
    16*4,                         // RegistersSize
    -1,                           // GrowthDirection
    17,                           // OutputRegisters
	cortex_m0_m4_stack_align,        // stack_alignment
    cortex_m_stack_offsets       // RegisterOffsets
};

/*********************************************************************
 *
 *       Static functions
 *
 **********************************************************************
 */

static void alloc_task_list(int count) {
    mynewt_os.task_details = (THREAD_DETAIL*) gdb_api->pfAlloc(
        count * sizeof(THREAD_DETAIL));
    memset(mynewt_os.task_details, 0, count * sizeof(THREAD_DETAIL));
    mynewt_os.num_task_details = count;
}

static void free_task_list() {
    U32 i;

    if (mynewt_os.task_details) {
        for (i = 0; i < mynewt_os.task_count; i++) {
            gdb_api->pfFree(mynewt_os.task_details[i].name);
        }
        gdb_api->pfFree(mynewt_os.task_details);
        mynewt_os.task_details = NULL;
        mynewt_os.num_task_details = 0;
    }
}

static int read_stack(U32 taskid) {
    U32 retval;
    U32 i;
    U32 task;
    U32 stack_ptr;
    U32 address;


    LOG("taskid: %d\n", taskid);

    //
    // search for thread ID
    //
    if (taskid == 0) {
        return -1;
    }

    task = 0;
    for (i = 0; i < mynewt_os.task_count; i++) {
        if (mynewt_os.task_details[i].id == taskid) {
            task = i;
            goto found;
            break;
        }
    }
    ERROR("Task not found.\n");
    return -2;

found:
    retval = gdb_api->pfReadU32(mynewt_os.task_details[task].addr, &stack_ptr);
    if (retval != 0) {
        ERROR("Error reading stack frame from embOS task.\n");
        return retval;
    }

    LOG("Read stack pointer at 0x%08X, value 0x%08X.\n",
        mynewt_os.task_details[task].addr, stack_ptr);

    if (stack_ptr == 0) {
        ERROR("Null stack pointer in task.\n");
        return -3;
    }

    mynewt_os.stacking_info = &cortex_m_stacking;

    address = stack_ptr;

    if (mynewt_os.stacking_info->growth_direction == 1)
        address -= mynewt_os.stacking_info->registers_size;

    retval = gdb_api->pfReadMem(address, (char*) stack_mem.data,
                                mynewt_os.stacking_info->registers_size);
    if (retval == 0) {
        ERROR("Error reading stack frame from task.\n");
        return retval;
    }

    LOG("Read stack frame at 0x%08X.\n", address);
    retval = gdb_api->pfLoad32TE(&stack_mem.data[0x24]);

    //
    // calculate stack pointer
    //
    if (mynewt_os.stacking_info->stack_align_f != NULL) {
        stack_mem.pointer = mynewt_os.stacking_info->stack_align_f(
            mynewt_os.stacking_info, stack_mem.data, stack_ptr);
    } else {
        stack_mem.pointer = stack_ptr
            - mynewt_os.stacking_info->growth_direction
            * mynewt_os.stacking_info->registers_size;
    }

    stack_mem.threadid = taskid;
    return 0;
}

/****************************************************************************/

static const char *task_state_desc(U8 state) {
    switch (state) {
    case 1:
        return "Running";
    case 2:
        return "Idle";
    default:
        return "Unknown";
    }
}

/*
 * This function is a hacky way to read memory. It was defined because
 * the pfReadMem function in GDB_API didn't work for me.
 */
static int read_mem(U32 addr, char *data, unsigned int size) {
    U32 i;
    U32 retval;

    for (i = 0; i < size; i += 4) {
        retval = gdb_api->pfReadU32(addr, (U32 *) data);
        if (retval != 0) {
            return retval;
        }

        LOG("Read 4 bytes @ addr 0x%08X (Data = 0x%08X)\n", addr,
            *(U32 *) data);
        addr += 4;
        data += 4;
    }
    return retval;
}

static int read_task(U32 addr, struct os_task *ptask) {
    U32 retval;

    retval = read_mem(addr, (char *) ptask, sizeof(struct os_task));

    if (retval != 0) {
        ERROR("Error reading task @ addr 0x%08X\n", addr);
        return retval;
    }

    LOG("Read task @ addr 0x%08X\n", addr);

    return retval;
}

static int read_task_name(U32 addr, char *name) {
    U32 retval;

    retval = read_mem(addr, name, OS_TASK_MAX_NAME_LEN);

    if (retval != 0) {
        ERROR("Error reading task name @ addr 0x%08X\n", addr);
        return retval;
    }

    LOG("Read task name @ addr 0x%08X, name=%s\n", addr, name);

    return retval;
}

static int read_task_count(U32 addr) {
    U32 retval;

    retval = gdb_api->pfReadU8(symbols[g_task_id].address,
                               &mynewt_os.task_count);
    if (retval != 0) {
        ERROR("Error reading g_task_id @ addr 0x%08X\n",
              symbols[g_task_id].address);
        return retval;
    }

    /* TODO: HACK! Eclipse doesn't like threadid=0? */
    mynewt_os.task_count += 1;

    LOG("Read g_task_id @ addr 0x%08X, value %d\n",
        symbols[g_task_id].address, mynewt_os.task_count);

    return 0;
}

static int read_current_task(U32 addr) {
    struct os_task current_task;
    char name[OS_TASK_MAX_NAME_LEN + 1];
    U32 retval;
    U32 current_task_ptr;

    retval = gdb_api->pfReadU32(addr, &current_task_ptr);
    if (retval != 0) {
        ERROR("Error reading g_current_task @ addr 0x%08X\n",
              symbols[g_current_task].address);
        return retval;
    }

    if (current_task_ptr == 0) {
        return 0;
    }

    LOG("Read current task ptr 0x%08X @ addr 0x%08X\n",
        current_task_ptr, symbols[g_current_task].address);

    retval = read_task(current_task_ptr, &current_task);
    if (retval != 0) {
        ERROR("Error reading current task @ addr 0x%08X\n",
              current_task_ptr);
        return retval;
    }
    LOG("Read current task @ addr 0x%08X\n", current_task_ptr);

    if (current_task.t_name == 0) {
        return 0;
    }

    retval = read_task_name(current_task.t_name, name);
    if (retval != 0) {
        ERROR("Error reading current task name @ addr 0x%08X\n",
              current_task.t_name);
        return retval;
    }

    /* TODO: HACK! Eclipse doesn't like threadid=0? */
    mynewt_os.current_taskid = current_task.t_taskid + 1;

    LOG("Read current task id 0x%02X\n", current_task.t_taskid);
    LOG("Read current task prio 0x%02X\n", current_task.t_prio);
    LOG("Read current task state 0x%02X\n", current_task.t_state);
    return retval;
}

static int read_task_list(U32 addr) {
    struct os_task_stailq task_list;
    struct os_task task_obj;
    char name[OS_TASK_MAX_NAME_LEN + 1];
    U8 tasks_found = 0;
    U32 task_list_size;
    U32 task_ptr;
    U32 retval;

    free_task_list();

    alloc_task_list(mynewt_os.task_count);
    if (!mynewt_os.task_details) {
        ERROR("Error allocating memory for %d threads.\n",
              mynewt_os.task_count);
        return -2;
    }

    retval = read_mem(addr, (char *) (&task_list), sizeof(task_list));
    if (retval != 0) {
        ERROR("Error reading task list @ addr 0x%08X\n", addr);
        return retval;
    }

    for (task_ptr = task_list.stqh_first; task_ptr;
         task_ptr = task_obj.t_os_task_list.stqe_next) {

        if (tasks_found >= mynewt_os.num_task_details) {
            ERROR("Found more tasks than expected\n");
            assert(0);
        }

        retval = read_task(task_ptr, &task_obj);
        if (retval != 0) {
            break;
        }

        /* TODO: HACK! Eclipse doesn't like threadid=0? */
        mynewt_os.task_details[tasks_found].id = task_obj.t_taskid + 1;
        mynewt_os.task_details[tasks_found].addr = task_ptr;

        if (task_obj.t_name == 0) {
            break;
        }

        retval = read_task_name((U32) task_obj.t_name, name);
        if (retval != 0) {
            break;
        }

        mynewt_os.task_details[tasks_found].name = (char*) gdb_api->pfAlloc(
            strlen(name) + 1);
        strncpy(mynewt_os.task_details[tasks_found].name, name,
                strlen(name) + 1);

        mynewt_os.task_details[tasks_found].prio = task_obj.t_prio;
        mynewt_os.task_details[tasks_found].state_str = task_state_desc(
            task_obj.t_state);

        LOG("Read task id 0x%02X\n", task_obj.t_taskid);
        LOG("Read task prio 0x%02X\n", task_obj.t_prio);
        LOG("Read task state 0x%02X\n", task_obj.t_state);

        tasks_found++;
    }

    return retval;
}

/*********************************************************************
 *
 *       Global functions
 *
 **********************************************************************
 */

EXPORT int RTOS_Init(const GDB_API *pAPI, U32 core) {
    gdb_api = pAPI;
    memset(&mynewt_os, 0, sizeof(mynewt_os));

    if (core == JLINK_CORE_CORTEX_M4 || core == JLINK_CORE_CORTEX_M0) {
        return 1;
    }
    return 0;
}

EXPORT U32 RTOS_GetVersion() {
    return PLUGIN_VERSION;
}

EXPORT RTOS_SYMBOLS* RTOS_GetSymbols() {
    return symbols;
}

EXPORT U32 RTOS_GetNumThreads() {
    LOG("count=%d\n", mynewt_os.task_count);
    return mynewt_os.task_count;
}

EXPORT U32 RTOS_GetCurrentThreadId() {
    LOG("threadid=%d\n",
        mynewt_os.current_taskid);
    return mynewt_os.current_taskid;
}

EXPORT U32 RTOS_GetThreadId(U32 n) {
    LOG("n=%d, threadid=%d\n", n,
        mynewt_os.task_details[n].id);
    return mynewt_os.task_details[n].id;
}

EXPORT int RTOS_GetThreadDisplay(char *pDisplay, U32 threadid) {
    const U32 reserved = 256;
    U32 i;
    U32 size;

    LOG("threadid=%d\n", threadid);

    if (mynewt_os.task_count) {
        for (i = 0; i < mynewt_os.task_count; i++) {
            if (mynewt_os.task_details[i].id == threadid) {
                size = 0;
                if (mynewt_os.task_details[i].name) {
                    size += snprintf(pDisplay, reserved, "%s",
                                     mynewt_os.task_details[i].name);
                }
                if (mynewt_os.task_details[i].state_str) {
                    if (size != 0) {
                        size += snprintf(pDisplay + size, reserved - size,
                                         " : ");
                    }
                    size += snprintf(pDisplay + size, reserved - size, "%s",
                                     mynewt_os.task_details[i].state_str);
                }

                size += snprintf(pDisplay + size, reserved - size, " [P: %d]",
                                 mynewt_os.task_details[i].prio);

                return size;
            }
        }
    }
    return 0;
}

EXPORT int RTOS_GetThreadReg(char *pHexRegVal, U32 RegIndex, U32 threadid) {
    int retval;
    I32 j;
    STACK_REGS reg;

    LOG("RegIndex=%d, threadid=%d\n", RegIndex, threadid);

    if (threadid == mynewt_os.current_taskid) {
        return -1; // Current thread or current execution returns CPU registers
    }

    //
    // load stack memory if necessary
    //
    if (stack_mem.threadid != threadid) {
        retval = read_stack(threadid);
        if (retval != 0) {
            return retval;
        }
    }

    reg = mynewt_os.stacking_info->register_offsets[RegIndex];

    for (j = 0; j < reg.bits / 8; j++) {
        if (reg.offset == -1) {
            pHexRegVal += snprintf(pHexRegVal, 3, "%02x", 0);
        } else if (reg.offset == -2) {
            pHexRegVal += snprintf(pHexRegVal, 3, "%02x",
                                   ((U8 *) &stack_mem.pointer)[j]);
        } else {
            pHexRegVal += snprintf(pHexRegVal, 3, "%02x", stack_mem.data[reg.offset + j]);
        }
    }
    LOG("Read task register 0x%02X, addr 0x%08X.\n", RegIndex,
        mynewt_os.stacking_info->register_offsets[RegIndex].offset);
    return 0;
}

EXPORT int RTOS_GetThreadRegList(char *pHexRegList, U32 threadid) {
    int retval;
    U32 i;
    I32 j;

    if (threadid == mynewt_os.current_taskid) {
        return -1; // Current thread or current execution returns CPU registers
    }

    //
    // load stack memory if necessary
    //
    if (stack_mem.threadid != threadid) {
        retval = read_stack(threadid);
        if (retval != 0) {
            return retval;
        }
    }

    for (i = 0; i < mynewt_os.stacking_info->output_registers; i++) {
        for (j = 0; j < mynewt_os.stacking_info->register_offsets[i].bits/8; j++) {
            if (mynewt_os.stacking_info->register_offsets[i].offset == -1) {
                pHexRegList += snprintf(pHexRegList, 3, "%02x", 0);
            } else if (mynewt_os.stacking_info->register_offsets[i].offset == -2) {
                pHexRegList += snprintf(pHexRegList, 3, "%02x", ((U8 *)&stack_mem.pointer)[j]);
            } else {
                pHexRegList += snprintf(pHexRegList, 3, "%02x",
                                        stack_mem.data[mynewt_os.stacking_info->register_offsets[i].offset + j]);
            }
        }
    }
    return 0;
}

EXPORT int RTOS_SetThreadReg(char* pHexRegVal, U32 RegIndex, U32 threadid) {
    return -1;
}

EXPORT int RTOS_SetThreadRegList(char *pHexRegList, U32 threadid) {
    return -1;
}

EXPORT int RTOS_UpdateThreads() {
    U32 retval;

    retval = read_task_count(symbols[g_task_id].address);
    if (retval != 0) {
        return retval;
    }

    retval = read_current_task(symbols[g_current_task].address);
    if (retval != 0) {
        return retval;
    }

    retval = read_task_list(symbols[g_os_task_list].address);
    if (retval != 0) {
        return retval;
    }

    return 0;
}
