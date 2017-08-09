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

/*********************************************************************
*
*       Static data
*
**********************************************************************
*/

static RTOS_SYMBOLS _Symbols[] = {
  { NULL, 0, 0 }
};

/*********************************************************************
*
*       Static functions
*
**********************************************************************
*/

/*********************************************************************
*
*       Global functions
*
**********************************************************************
*/

EXPORT int RTOS_Init(const GDB_API *pAPI, U32 core) {
  return 1;
}

EXPORT U32 RTOS_GetVersion() {
  return PLUGIN_VERSION;
}

EXPORT RTOS_SYMBOLS* RTOS_GetSymbols() {
  return _Symbols;
}

EXPORT U32 RTOS_GetNumThreads() {
  return 0;
}

EXPORT U32 RTOS_GetCurrentThreadId() {
  return 0;
}

EXPORT U32 RTOS_GetThreadId(U32 n) {
  return 0;
}

EXPORT int RTOS_GetThreadDisplay(char *pDisplay, U32 threadid) {
  return 0;
}

EXPORT int RTOS_GetThreadReg(char *pHexRegVal, U32 RegIndex, U32 threadid) {
  return -1;
}

EXPORT int RTOS_GetThreadRegList(char *pHexRegList, U32 threadid) {
  return -1;
}

EXPORT int RTOS_SetThreadReg(char* pHexRegVal, U32 RegIndex, U32 threadid) {
  return -1;
}

EXPORT int RTOS_SetThreadRegList(char *pHexRegList, U32 threadid) {
  return -1;
}

EXPORT int RTOS_UpdateThreads() {
  return 0;
}
