//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
//       conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
//       conditions and the following disclaimer in the documentation and/or other materials 
//       provided with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
//       endorse or promote products derived from this software without specific prior written 
//       permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#ifndef REFLECTIVELOADER_H
#define REFLECTIVELOADER_H
//===============================================================================================//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
//===============================================================================================//
#define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR      0
#define REFLECTIVEDLLINJECTION_VIA_REFLECTIVELOADER        1

#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN              1
//===============================================================================================//
// We implement a minimal GetProcAddress to avoid using the native one which may be hooked. 
// However this may fail if the export are forwarded.
#define USE_CUSTOM_GETPROCADDRESS	FALSE
//===============================================================================================//
#define DLL_QUERY_HMODULE   6
//===============================================================================================//
#ifdef _MSC_VER
#pragma intrinsic( _ReturnAddress )
#endif
// This function can not be inlined as it need to arguments and we need to retrieve the RetAddress
__declspec(noinline)
ULONG_PTR caller( VOID );
//===============================================================================================//
// --- Хак для MinGW: если winternl.h не содержит BaseDllName, определяем только BaseDllName ---
#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))
#endif

#ifndef LDR_DATA_TABLE_ENTRY_HAS_BASEDLLNAME
// Если winternl.h не содержит BaseDllName, определяем offset вручную (только для MinGW)
#define LDR_DATA_TABLE_ENTRY_HAS_BASEDLLNAME 0
#else
#define LDR_DATA_TABLE_ENTRY_HAS_BASEDLLNAME 1
#endif
//===============================================================================================//
// Минимальные определения структур для обхода winternl.h
#if defined(_WIN64)
#define OFFSET_LDR_DATA_TABLE_ENTRY_BASEDLLNAME 0x58
#else
#define OFFSET_LDR_DATA_TABLE_ENTRY_BASEDLLNAME 0x2C
#endif

// Минимальная структура PEB (только нужные поля)
typedef struct _PEB_LDR_DATA_MIN {
    BYTE       Reserved1[16];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA_MIN, *PPEB_LDR_DATA_MIN;

typedef struct _PEB_MIN {
    BYTE          Reserved1[2];
    BYTE          BeingDebugged;
    BYTE          Reserved2[1];
    PVOID         Reserved3[2];
    PPEB_LDR_DATA_MIN Ldr;
} PEB_MIN, *PPEB_MIN;

// Макрос для получения BaseDllName через offset
#define GET_BASEDLLNAME(entry) ((UNICODE_STRING*)((BYTE*)(entry) + OFFSET_LDR_DATA_TABLE_ENTRY_BASEDLLNAME))
//===============================================================================================//
#endif
//===============================================================================================// 