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
};

extern HANDLE g_hDev;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;    //˫������
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

// ��DeviceIoControl�ķ�װ.
//void ark_readprocmemroy(HANDLE hDev, int pid, char* dest, int size);

