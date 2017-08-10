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

struct os_task_stailq {
    U32 stqh_first;/* first element */
    U32 stqh_last;/* addr of last next element */
};

#define	STAILQ_FIRST(head)	((head)->stqh_first)

#define	STAILQ_NEXT(elm, field)	((elm)->field.stqe_next)

#define	STAILQ_ENTRY(type)						\
struct {								\
	U32 stqe_next;	/* next element */			\
}

#define	TAILQ_ENTRY(type)						\
struct {								\
	U32 tqe_next;	/* next element */			\
	U32 tqe_prev;	/* address of previous next element */	\
}

#define	SLIST_ENTRY(type)                               \
struct {                                                \
    U32 sle_next;  /* next element */          \
}

struct os_sanity_check;

struct os_sanity_check {
    U32 sc_checkin_last;
    U32 sc_checkin_itvl;
    U32 sc_func;
    U32 sc_arg;

    SLIST_ENTRY(U32)
    sc_next;
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
    STAILQ_ENTRY(U32)
    t_os_task_list;

    /* Used to chain task to either the run or sleep list */
    TAILQ_ENTRY(U32)
    t_os_list;

    /* Used to chain task to an object such as a semaphore or mutex */
    SLIST_ENTRY(U32)
    t_obj_list;
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
  U8  Data[0xD0];     // stack data, maximum possible stack size
  U32 Pointer;        // stack pointer
  U32 ThreadID;       // thread ID
} STACK_MEM;

typedef struct {
  signed short   offset;
  unsigned short bits;
} STACK_REGS;

typedef struct _Stacking {
  unsigned char     RegistersSize;
  signed char       GrowthDirection;
  unsigned char     OutputRegisters;
  U32             (*CalcProcessStack) (const struct _Stacking *Stacking, const U8 *StackData, U32 StackPtr);
  const STACK_REGS *RegisterOffsets;
} STACKING;

/*********************************************************************
 *
 *       Static data
 *
 **********************************************************************
 */

static const GDB_API *_pAPI;

static STACK_MEM _StackMem;

static struct {
    const STACKING *StackingInfo;
    U32 current_threadid;
    U8 thread_count;
    U32 num_thread_details;
    THREAD_DETAIL *thread_details;
} _MynewtOS;

static const STACK_REGS _CortexM4FStackOffsets[] = {
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

static const STACK_REGS _CortexM4FStackOffsetsVFP[] = {
  { 0x68, 32 },    // R0
  { 0x6C, 32 },    // R1
  { 0x70, 32 },    // R2
  { 0x74, 32 },    // R3
  { 0x04, 32 },    // R4
  { 0x08, 32 },    // R5
  { 0x0C, 32 },    // R6
  { 0x10, 32 },    // R7
  { 0x14, 32 },    // R8
  { 0x18, 32 },    // R9
  { 0x1C, 32 },    // R10
  { 0x20, 32 },    // R11
  { 0x78, 32 },    // R12
  { -2,   32 },    // SP
  { 0x7C, 32 },    // LR
  { 0x80, 32 },    // PC
  { 0x84, 32 },    // XPSR
  { -1,   32 },    // MSP
  { -1,   32 },    // PSP
  { -1,   32 },    // PRIMASK
  { -1,   32 },    // BASEPRI
  { -1,   32 },    // FAULTMASK
  { -1,   32 },    // CONTROL
  { 0xC8, 32 },    // FPSCR
  { 0x88, 32 },    // S0
  { 0x8C, 32 },    // S1
  { 0x90, 32 },    // S2
  { 0x94, 32 },    // S3
  { 0x98, 32 },    // S4
  { 0x9C, 32 },    // S5
  { 0xA0, 32 },    // S6
  { 0xA4, 32 },    // S7
  { 0xA8, 32 },    // S8
  { 0xAC, 32 },    // S9
  { 0xB0, 32 },    // S10
  { 0xB4, 32 },    // S11
  { 0xB8, 32 },    // S12
  { 0xBC, 32 },    // S13
  { 0xC0, 32 },    // S14
  { 0xC4, 32 },    // S15
  { 0x28, 32 },    // S16
  { 0x2C, 32 },    // S17
  { 0x30, 32 },    // S18
  { 0x34, 32 },    // S19
  { 0x38, 32 },    // S20
  { 0x3C, 32 },    // S21
  { 0x40, 32 },    // S22
  { 0x44, 32 },    // S23
  { 0x48, 32 },    // S24
  { 0x4C, 32 },    // S25
  { 0x50, 32 },    // S26
  { 0x54, 32 },    // S27
  { 0x58, 32 },    // S28
  { 0x5C, 32 },    // S29
  { 0x60, 32 },    // S30
  { 0x64, 32 },    // S31
};

static RTOS_SYMBOLS _Symbols[] = {
    { "g_task_id", 0, 0 },
    { "g_current_task", 0, 0 },
    { "g_os_task_list", 0, 0 },
    { NULL, 0, 0 } };

enum RTOS_Symbol_Values {
    g_task_id = 0,
    g_current_task,
    g_os_task_list,
};

static U32 _DoCortexMStackAlign(const STACKING *stacking, const U8 *StackData, U32 StackPtr, size_t XPSROffset) {
  const U32 ALIGN_NEEDED = (1 << 9);
  U32 xpsr;
  U32 NewStackPtr;

  NewStackPtr = StackPtr - stacking->GrowthDirection * stacking->RegistersSize;
  xpsr = _pAPI->pfLoad32TE(&StackData[XPSROffset]);
  if ((xpsr & ALIGN_NEEDED) != 0) {
    _pAPI->pfWarnOutf("XPSR(0x%08X) indicated stack alignment was necessary.\n", xpsr);
    NewStackPtr -= (stacking->GrowthDirection * 4);
  }
  return NewStackPtr;
}

static U32 _CortexM4FStackAlign(const STACKING *stacking, const U8 *StackData, U32 StackPtr) {
  const int XPSROffset = 0x44;
  return _DoCortexMStackAlign(stacking, StackData, StackPtr, XPSROffset);
}

static U32 _CortexM4FStackAlignVFP(const STACKING *stacking, const U8 *StackData, U32 StackPtr) {
  const int XPSROffset = 0x84;
  return _DoCortexMStackAlign(stacking, StackData, StackPtr, XPSROffset);
}

static const STACKING _CortexM4FStacking = {
  0x48,                         // RegistersSize
  -1,                           // GrowthDirection
  17,                           // OutputRegisters
  _CortexM4FStackAlign,         // stack_alignment
  _CortexM4FStackOffsets        // RegisterOffsets
};

static const STACKING _CortexM4FStackingVFP = {
  0xD0,                         // RegistersSize
  -1,                           // GrowthDirection
  17,                           // OutputRegisters
  _CortexM4FStackAlignVFP,      // stack_alignment
  _CortexM4FStackOffsetsVFP     // RegisterOffsets
};

/*********************************************************************
 *
 *       Static functions
 *
 **********************************************************************
 */

/*********************************************************************
 *
 *       _AllocThreadlist(int count)
 *
 *  Function description
 *    Allocates a thread list for count entries.
 */
static void _AllocThreadlist(int count) {
    _MynewtOS.thread_details = (THREAD_DETAIL*) _pAPI->pfAlloc(
            count * sizeof(THREAD_DETAIL));
    memset(_MynewtOS.thread_details, 0, count * sizeof(THREAD_DETAIL));
    _MynewtOS.num_thread_details = count;
}

/*********************************************************************
 *
 *       _FreeThreadlist()
 *
 *  Function description
 *    Frees the thread list
 */
static void _FreeThreadlist() {
    U32 i;

    if (_MynewtOS.thread_details) {
        for (i = 0; i < _MynewtOS.thread_count; i++) {
            _pAPI->pfFree(_MynewtOS.thread_details[i].name);
        }
        _pAPI->pfFree(_MynewtOS.thread_details);
        _MynewtOS.thread_details = NULL;
        _MynewtOS.num_thread_details = 0;
    }
}

/*********************************************************************
 *
 *       _ReadStack(U32 threadid)
 *
 *  Function description
 *    Reads the task stack of the task with the ID threadid into _StackMem.
 */
static int _ReadStack(U32 threadid) {
    U32 retval;
    U32 i;
    U32 task;
    U32 StackPtr;
    U32 PC;
    U32 address;
    //
    // search for thread ID
    //
    task = 0;
    for (i = 0; i < _MynewtOS.thread_count; i++) {
        if (_MynewtOS.thread_details[i].id == threadid) {
            task = i;
            goto found;
            break;
        }
    }
    _pAPI->pfErrorOutf("Task not found.\n");
    return -2;

found:
    retval = _pAPI->pfReadU32(_MynewtOS.thread_details[task].addr, &StackPtr);
    if (retval != 0) {
        _pAPI->pfErrorOutf("Error reading stack frame from embOS task.\n");
        return retval;
    }

    _pAPI->pfWarnOutf("Read stack pointer at 0x%08X, value 0x%08X.\n",
            _MynewtOS.thread_details[task].addr, StackPtr);

    if (StackPtr == 0) {
        _pAPI->pfErrorOutf("Null stack pointer in task.\n");
        return -3;
    }

    _MynewtOS.StackingInfo = &_CortexM4FStacking;

//start:
    address = StackPtr;

    if (_MynewtOS.StackingInfo->GrowthDirection == 1)
        address -= _MynewtOS.StackingInfo->RegistersSize;

    retval = _pAPI->pfReadMem(address, (char*) _StackMem.Data,
            _MynewtOS.StackingInfo->RegistersSize);
    if (retval == 0) {
        _pAPI->pfErrorOutf("Error reading stack frame from task.\n");
        return retval;
    }

    _pAPI->pfWarnOutf("Read stack frame at 0x%08X.\n", address);
    retval = _pAPI->pfLoad32TE(&_StackMem.Data[0x24]);
//
//    if (_MynewtOS.StackingInfo == &_CortexM4FStacking && !(retval & 0x10)) {
//        _pAPI->pfWarnOutf(
//                "LR(0x%08X) indicated task uses VFP, reading stack frame again.\n",
//                retval);
//        _MynewtOS.StackingInfo = &_CortexM4FStackingVFP;
//        goto start;
//    }
//
    //
    // calculate stack pointer
    //
//    if (_MynewtOS.StackingInfo->CalcProcessStack != NULL) {
//        _StackMem.Pointer = _MynewtOS.StackingInfo->CalcProcessStack(
//                _MynewtOS.StackingInfo, _StackMem.Data, StackPtr);
//    } else {
//        _StackMem.Pointer = StackPtr
//                - _MynewtOS.StackingInfo->GrowthDirection
//                        * _MynewtOS.StackingInfo->RegistersSize;
//    }

    _StackMem.Pointer = StackPtr +4;

    _StackMem.ThreadID = threadid;
    return 0;
}

/****************************************************************************/

static const char *taskStateDesc(U8 state) {
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
static int pfReadMem(U32 addr, char *data, unsigned int size) {
    U32 i;
    U32 retval;

    for (i = 0; i < size; i += 4) {
        retval = _pAPI->pfReadU32(addr, (U32 *) data);
        if (retval != 0) {
            return retval;
        }

        _pAPI->pfWarnOutf("Read 4 bytes @ addr 0x%08X (Data = 0x%08X)\n", addr,
                *(U32 *) data);
        addr += 4;
        data += 4;
    }
    return retval;
}

static int readTask(U32 addr, struct os_task *ptask) {
    U32 retval;

    retval = pfReadMem(addr, (char *) ptask, sizeof(struct os_task));

    if (retval != 0) {
        _pAPI->pfErrorOutf("Error reading task @ addr 0x%08X\n", addr);
        return retval;
    }

    _pAPI->pfWarnOutf("Read task @ addr 0x%08X\n", addr);

    return retval;
}

static int readTaskName(U32 addr, char *name) {
    U32 retval;

    retval = pfReadMem(addr, name, OS_TASK_MAX_NAME_LEN);

    if (retval != 0) {
        _pAPI->pfErrorOutf("Error reading task name @ addr 0x%08X\n", addr);
        return retval;
    }

    _pAPI->pfWarnOutf("Read task name @ addr 0x%08X, name=%s\n", addr, name);

    return retval;
}

static int readTaskCount(U32 addr) {
    U32 retval;

    retval = _pAPI->pfReadU8(_Symbols[g_task_id].address,
            &_MynewtOS.thread_count);
    if (retval != 0) {
        _pAPI->pfErrorOutf("Error reading g_task_id @ addr 0x%08X\n",
                _Symbols[g_task_id].address);
        return retval;
    }

    /* TODO: HACK! Eclipse doesn't like threadid=0? */
    _MynewtOS.thread_count += 1;

    _pAPI->pfWarnOutf("Read g_task_id @ addr 0x%08X, value %d\n",
            _Symbols[g_task_id].address, _MynewtOS.thread_count);

    return 0;
}

static int readCurrentTask(U32 addr) {
    struct os_task current_task;
    char name[OS_TASK_MAX_NAME_LEN + 1];
    U32 retval;
    U32 current_task_ptr;

    retval = _pAPI->pfReadU32(addr, &current_task_ptr);
    if (retval != 0) {
        _pAPI->pfErrorOutf("Error reading g_current_task @ addr 0x%08X\n",
                _Symbols[g_current_task].address);
        return retval;
    }

    if (current_task_ptr == 0) {
        return 0;
    }

    _pAPI->pfWarnOutf("Read current task ptr 0x%08X @ addr 0x%08X\n",
            current_task_ptr, _Symbols[g_current_task].address);

    retval = readTask(current_task_ptr, &current_task);
    if (retval != 0) {
        _pAPI->pfErrorOutf("Error reading current task @ addr 0x%08X\n",
                current_task_ptr);
        return retval;
    }
    _pAPI->pfWarnOutf("Read current task @ addr 0x%08X\n", current_task_ptr);

    if (current_task.t_name == 0) {
        return 0;
    }

    retval = readTaskName(current_task.t_name, name);
    if (retval != 0) {
        _pAPI->pfErrorOutf("Error reading current task name @ addr 0x%08X\n",
                current_task.t_name);
        return retval;
    }

    /* TODO: HACK! Eclipse doesn't like threadid=0? */
    _MynewtOS.current_threadid = current_task.t_taskid + 1;

    _pAPI->pfWarnOutf("Read current task id 0x%02X\n", current_task.t_taskid);
    _pAPI->pfWarnOutf("Read current task prio 0x%02X\n", current_task.t_prio);
    _pAPI->pfWarnOutf("Read current task state 0x%02X\n", current_task.t_state);
    return retval;
}

static int readTaskList(U32 addr) {
    struct os_task_stailq task_list;
    struct os_task task_obj;
    char name[OS_TASK_MAX_NAME_LEN + 1];
    U8 tasks_found = 0;
    U32 task_list_size;
    U32 task_ptr;
    U32 retval;

    _FreeThreadlist();

    _AllocThreadlist(_MynewtOS.thread_count);
    if (!_MynewtOS.thread_details) {
        _pAPI->pfErrorOutf("Error allocating memory for %d threads.\n",
                _MynewtOS.thread_count);
        return -2;
    }

    retval = pfReadMem(addr, (char *) (&task_list), sizeof(task_list));
    if (retval != 0) {
        _pAPI->pfErrorOutf("Error reading task list @ addr 0x%08X\n", addr);
        return retval;
    }

    for (task_ptr = task_list.stqh_first; task_ptr;
            task_ptr = task_obj.t_os_task_list.stqe_next) {

        if (tasks_found >= _MynewtOS.num_thread_details) {
            _pAPI->pfErrorOutf("Found more tasks than expected\n");
            assert(0);
        }

        retval = readTask(task_ptr, &task_obj);
        if (retval != 0) {
            break;
        }

        /* TODO: HACK! Eclipse doesn't like threadid=0? */
        _MynewtOS.thread_details[tasks_found].id = task_obj.t_taskid + 1;
        _MynewtOS.thread_details[tasks_found].addr = task_ptr;

        if (task_obj.t_name == 0) {
            break;
        }

        retval = readTaskName((U32) task_obj.t_name, name);
        if (retval != 0) {
            break;
        }

        _MynewtOS.thread_details[tasks_found].name = (char*) _pAPI->pfAlloc(
                strlen(name) + 1);
        strncpy(_MynewtOS.thread_details[tasks_found].name, name,
                strlen(name) + 1);

        _MynewtOS.thread_details[tasks_found].prio = task_obj.t_prio;
        _MynewtOS.thread_details[tasks_found].state_str = taskStateDesc(
                task_obj.t_state);

        _pAPI->pfWarnOutf("Read task id 0x%02X\n", task_obj.t_taskid);
        _pAPI->pfWarnOutf("Read task prio 0x%02X\n", task_obj.t_prio);
        _pAPI->pfWarnOutf("Read task state 0x%02X\n", task_obj.t_state);

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
    _pAPI = pAPI;
    memset(&_MynewtOS, 0, sizeof(_MynewtOS));
    return 1;
}

EXPORT U32 RTOS_GetVersion() {
    return PLUGIN_VERSION;
}

EXPORT RTOS_SYMBOLS* RTOS_GetSymbols() {
    return _Symbols;
}

EXPORT U32 RTOS_GetNumThreads() {
    _pAPI->pfWarnOutf("GetNumThreads: count=%d\n", _MynewtOS.thread_count);
    return _MynewtOS.thread_count;
}

EXPORT U32 RTOS_GetCurrentThreadId() {
    _pAPI->pfWarnOutf("GetCurrentThreadId: threadid=%d\n",
            _MynewtOS.current_threadid);
    return _MynewtOS.current_threadid;
}

EXPORT U32 RTOS_GetThreadId(U32 n) {
    _pAPI->pfWarnOutf("GetThreadID: n=%d, threadid=%d\n", n,
            _MynewtOS.thread_details[n].id);
    return _MynewtOS.thread_details[n].id;
}

EXPORT int RTOS_GetThreadDisplay(char *pDisplay, U32 threadid) {
    const U32 reserved = 256;
    U32 i;
    U32 size;

    _pAPI->pfWarnOutf("GetThreadDisplay: threadid=%d\n", threadid);

    if (_MynewtOS.thread_count) {
        for (i = 0; i < _MynewtOS.thread_count; i++) {
            if (_MynewtOS.thread_details[i].id == threadid) {
                size = 0;
                if (_MynewtOS.thread_details[i].name) {
                    size += snprintf(pDisplay, reserved, "%s",
                            _MynewtOS.thread_details[i].name);
                }
                if (_MynewtOS.thread_details[i].state_str) {
                    if (size != 0) {
                        size += snprintf(pDisplay + size, reserved - size,
                                " : ");
                    }
                    size += snprintf(pDisplay + size, reserved - size, "%s",
                            _MynewtOS.thread_details[i].state_str);
                }

                size += snprintf(pDisplay + size, reserved - size, " [P: %d]",
                        _MynewtOS.thread_details[i].prio);

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

    _pAPI->pfWarnOutf("GetThreadDisplay: RegIndex=%d, threadid=%d\n", RegIndex, threadid);

    if (threadid == _MynewtOS.current_threadid) {
        return -1; // Current thread or current execution returns CPU registers
    }

    //
    // load stack memory if necessary
    //
    if (_StackMem.ThreadID != threadid) {
        retval = _ReadStack(threadid);
        if (retval != 0) {
            return retval;
        }
    }
    reg = _MynewtOS.StackingInfo->RegisterOffsets[RegIndex];

//    if (RegIndex > 0x16 && _MynewtOS.StackingInfo == &_CortexM4FStackingVFP) {
        for (j = 0; j < reg.bits / 8; j++) {
            if (reg.offset == -1) {
                pHexRegVal += snprintf(pHexRegVal, 3, "%02x", 0);
            } else if (reg.offset == -2) {
                pHexRegVal += snprintf(pHexRegVal, 3, "%02x",
                        ((U8 *) &_StackMem.Pointer)[j]);
            } else {
                pHexRegVal += snprintf(pHexRegVal, 3, "%02x", _StackMem.Data[reg.offset + j]);
            }
        }
        _pAPI->pfWarnOutf("Read task register 0x%02X, addr 0x%08X.\n", RegIndex,
                _MynewtOS.StackingInfo->RegisterOffsets[RegIndex].offset);
        return 0;
//    } else {
//        return -1;
//    }
}

EXPORT int RTOS_GetThreadRegList(char *pHexRegList, U32 threadid) {
    int retval;
    U32 i;
    I32 j;

    if (threadid == _MynewtOS.current_threadid) {
      return -1; // Current thread or current execution returns CPU registers
    }

    //
    // load stack memory if necessary
    //
    if (_StackMem.ThreadID != threadid) {
      retval = _ReadStack(threadid);
      if (retval != 0) {
        return retval;
      }
    }

    for (i = 0; i < _MynewtOS.StackingInfo->OutputRegisters; i++) {
      for (j = 0; j < _MynewtOS.StackingInfo->RegisterOffsets[i].bits/8; j++) {
        if (_MynewtOS.StackingInfo->RegisterOffsets[i].offset == -1) {
          pHexRegList += snprintf(pHexRegList, 3, "%02x", 0);
        } else if (_MynewtOS.StackingInfo->RegisterOffsets[i].offset == -2) {
          pHexRegList += snprintf(pHexRegList, 3, "%02x", ((U8 *)&_StackMem.Pointer)[j]);
        } else {
          pHexRegList += snprintf(pHexRegList, 3, "%02x",
            _StackMem.Data[_MynewtOS.StackingInfo->RegisterOffsets[i].offset + j]);
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

    retval = readTaskCount(_Symbols[g_task_id].address);
    if (retval != 0) {
        return retval;
    }

    retval = readCurrentTask(_Symbols[g_current_task].address);
    if (retval != 0) {
        return retval;
    }

    retval = readTaskList(_Symbols[g_os_task_list].address);
    if (retval != 0) {
        return retval;
    }

    return 0;
}
