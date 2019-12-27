#pragma once
#include <iostream>
#include <windows.h>
#include <winioctl.h>
//#include <ntdef.h>
#include <SubAuth.h>

#define MYCTLCODE( code ) CTL_CODE(FILE_DEVICE_UNKNOWN,0x800+(code), METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef enum MyCtlCode
{
	enumDriver1 = MYCTLCODE(0),
	enumDriver2 = MYCTLCODE(1),
	enumProcess1 = MYCTLCODE(2),
	enumProcess2 = MYCTLCODE(3),
	enumModule1 = MYCTLCODE(4),
	enumModule2 = MYCTLCODE(5),
	enumThread1 = MYCTLCODE(6),
	enumThread2 = MYCTLCODE(7),
	enumIDT1 = MYCTLCODE(8),
	enumGDT1 = MYCTLCODE(9),
	HideDriver = MYCTLCODE(10),
	HideProcess = MYCTLCODE(11),
	KillProcess = MYCTLCODE(12),
	enumFile1 = MYCTLCODE(13),
	enumFile2 = MYCTLCODE(14),
	deleteFile = MYCTLCODE(15),
	enumSSDT1 = MYCTLCODE(16),
	enumSSDT2 = MYCTLCODE(17),
	hookSysEnter = MYCTLCODE(18),
	kernelReload = MYCTLCODE(19),
	enumRegTable1 = MYCTLCODE(20),
	enumRegTable2 = MYCTLCODE(21),

};

extern HANDLE g_hDev;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;    //双向链表
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		}s1;
	}u1;
	union {
		struct {
			ULONG TimeDateStamp;
		}s2;
		struct {
			PVOID LoadedImports;
		}s3;
	}u2;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _DRIVERINFO
{
	PVOID base;
	DWORD size;
	TCHAR name[260];
}DRIVERINFO, *PDRIVERINFO;

typedef struct _PROCESSINFO
{
	DWORD PID;
	TCHAR name[260];
}PROCESSINFO, *PPROCESSINFO;

typedef struct _THREADINFO
{
	DWORD TID;
}THREADINFO, *PTHREADINFO;

typedef struct _MODULEINFO
{
	PVOID base;
	DWORD size;
	TCHAR name[260];
}MODULEINFO, *PMODULEINFO;
typedef struct _IDTINFO
{
	ULONG uSelector;
	ULONG addr;
	ULONG GateType;
	ULONG DPL;
}IDTINFO, *PIDTINFO;

typedef struct _GDTINFO
{
	UINT64 Limit : 20;
	UINT64 Base : 32;
	UINT64 P : 1;
	UINT64 S : 1;
	UINT64 Type : 4;
	UINT64 DPL : 2;
	UINT64 D_B : 1;
	UINT64 G : 1;
}GDTINFO, *PGDTINFO;

typedef struct _FILEINFO
{
	TCHAR fileName[260];
	LARGE_INTEGER size;
	DWORD attribute;
	LARGE_INTEGER createTime;
	LARGE_INTEGER changeTime;
}FILEINFO, *PFILEINFO;
typedef struct _FILEINFO2
{
	CString filePath;
	WORD index;
}FILEINFO2, *PFILEINFO2;
typedef struct _SSDTINFO
{
	ULONG funcAddr;
	//ULONG paramCount;
}SSDTINFO, *PSSDTINFO;
typedef struct _REGTABLEINFO
{
	TCHAR name[260];
}REGTABLEINFO, *PREGTABLEINFO;

// 对DeviceIoControl的封装.
//void ark_readprocmemroy(HANDLE hDev, int pid, char* dest, int size);

