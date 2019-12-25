#include <ntifs.h>
#include <ntddk.h>
#include <stdlib.h>
#include <tchar.h>
#include <wchar.h>

// 设备\符号链接名
#define NAME_DEVICE L"\\Device\\deviceARK"
#define NAME_SYMBOL L"\\DosDevices\\deviceARK"

#define MAKELONG(a,b) ((LONG)(((UINT16)(((DWORD_PTR)(a))&0xffff)) | ((ULONG)((UINT16)(((DWORD_PTR)(b))& 0xffff)))<<16))

// 事先声明函数
NTKERNELAPI CHAR* PsGetProcessImageFileName(PEPROCESS proc);
NTKERNELAPI struct _PEB* PsGetProcessPeb(PEPROCESS proc);

struct _PEB
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;
	UCHAR BitField;
	void* Mutant;                                                           //0x4
	void* ImageBaseAddress;                                                 //0x8
	struct _PEB_LDR_DATA* Ldr;
};
struct _PEB_LDR_DATA
{
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	VOID* SsHandle;                                                         //0x8
	struct _LIST_ENTRY InLoadOrderModuleList;                               //0xc
	struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x14
	struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x1c
	VOID* EntryInProgress;                                                  //0x24
	UCHAR ShutdownInProgress;                                               //0x28
	VOID* ShutdownThreadId;                                                 //0x2c
};
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
	ULONG size;
	TCHAR name[260];
}DRIVERINFO, *PDRIVERINFO;
typedef struct _PROCESSINFO
{
	ULONG PID;
	TCHAR name[260];
}PROCESSINFO, *PPROCESSINFO;
typedef struct _THREADINFO
{
	ULONG TID;
}THREADINFO, *PTHREADINFO;
typedef struct _MODULEINFO
{
	PVOID base;
	ULONG size;
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

typedef struct _IDT_INFO
{
	UINT16 uIdtLimit;
	UINT16 uLowIdtBase;
	UINT16 uHighIdtBase;
}IDT_INFO,*PIDT_INFO;
typedef struct _IDT_ENTRY
{
	UINT16 uSelector;
	UINT16 uOffsetLow;
	UINT16 uOffsetHigh;
	UINT8 GateType : 4;
	UINT8 DPL : 2;
}IDT_ENTRY, *PIDT_ENTRY;
typedef struct _GDT_INFO
{
	UINT16 uGdtLimit;
	UINT16 uLowGdtBase;
	UINT16 uHighGdtBase;
}GDT_INFO, *PGDT_INFO;
typedef struct _GDT_ENTRY
{
	UINT64 Limit_0_15 : 16;
	UINT64 Limit_16_19 : 4;
	UINT64 Base16_31 : 16;
	UINT64 Base0_7 : 8;
	UINT64 Base24_31 : 8;
	UINT64 Type : 4;
	UINT64 S : 1;
	UINT64 DPL : 2;
	UINT64 P : 1;
	UINT64 D_B : 1;
	UINT64 G : 1;
}GDT_ENTRY, *PGDT_ENTRY;

// 自定义控制码
#define MYCTLCODE(code) CTL_CODE(FILE_DEVICE_UNKNOWN,0x800+(code),METHOD_BUFFERED,FILE_ANY_ACCESS)
typedef enum _MyCtlCode
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
}MyCtlCode;

// 自定义控制码的派遣函数
NTSTATUS OnEnumDriver1(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// 返回状态
	// 1 获取双向链表首地址
	PDRIVER_OBJECT pDriver = pDevice->DriverObject;// 设备对象归属的驱动对象
	PLDR_DATA_TABLE_ENTRY pLdr = pDriver->DriverSection;// 多条驱动信息构成的双向链表
	PLDR_DATA_TABLE_ENTRY pBegin = pLdr;// 链表首地址
	// 2 获取IO缓存区(二者共用
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;
	// 若调试状态则下断
#ifdef _DEBUG
	KdBreakPoint();
#endif
	// 3 获取驱动个数
	ULONG driverCount = 0;
	__try
	{
		do
		{
			driverCount++;
			pLdr = (PLDR_DATA_TABLE_ENTRY)pLdr->InLoadOrderLinks.Flink;
		} while (pBegin != pLdr);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("Exception: 0x%08X\n", GetExceptionCode()));
	}
	// 4 数据传输-写入3环
	RtlCopyMemory(pBuff, &driverCount, sizeof(driverCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = sizeof(driverCount);// 总共传输字节数
	return status;
}
NTSTATUS OnEnumDriver2(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// 返回状态
	// 1 获取双向链表基地址
	PDRIVER_OBJECT pDriver = pDevice->DriverObject;
	PLDR_DATA_TABLE_ENTRY pLdr = pDriver->DriverSection;
	PLDR_DATA_TABLE_ENTRY pBegin = pLdr;
	// 2 获取IO缓存区(二者共用
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 将数据写入3环缓冲区
	PDRIVERINFO pDriverInfo = (PDRIVERINFO)pBuff;
	__try
	{
		do
		{
			// 写入各字段
			//RtlCopyMemory(pDriverInfo->name, pLdr->FullDllName.Buffer, pLdr->FullDllName.Length);// here 乱码
			_tcscpy_s(pDriverInfo->name, sizeof(pDriverInfo->name), pLdr->FullDllName.Buffer);
			pDriverInfo->base = pLdr->DllBase;
			pDriverInfo->size = pLdr->SizeOfImage;

			pDriverInfo++;// 指针后移
			pLdr = (PLDR_DATA_TABLE_ENTRY)pLdr->InLoadOrderLinks.Flink;
		} while (pBegin != pLdr);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("Exception: 0x%08X\n", GetExceptionCode()));
	}
	// 4 设置完成状态及传输数据量
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = (ULONG)pDriverInfo - (ULONG)pBuff;// 尾地址-首地址=传输大小
	return status;
}
NTSTATUS OnEnumProcess1(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// 返回状态
	// 2 获取IO缓存区(二者共用
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// 若调试状态则下断
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 获取进程数
	ULONG ProcessCount = 0;
	PEPROCESS proc = NULL;
	// 设定PID范围,循环遍历
	for (int i = 4; i < 100000; i += 4)
	{
		// 若通过PID能找到EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &proc)))
		{
			// 进一步判断进程是否有效
			ULONG TableCode = *(ULONG*)((ULONG)proc + 0xF4);
			if (TableCode)
			{
				ProcessCount++;// 个数+1 
				KdPrint(("%d : %s\n", ProcessCount, PsGetProcessImageFileName(proc)));
				ObDereferenceObject(proc);// 递减引用计数
			}

		}
	}
	// 4 数据传输-写入3环
	RtlCopyMemory(pBuff, &ProcessCount, sizeof(ProcessCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = sizeof(ProcessCount);// 总共传输字节数
	return status;
}
NTSTATUS OnEnumProcess2(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// 返回状态
// 2 获取IO缓存区(二者共用
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// 若调试状态则下断
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 获取进程数
	//ULONG ProcessCount = 0;
	PEPROCESS proc = NULL;
	PPROCESSINFO pProcessInfo = (PPROCESSINFO)pBuff;
	// 设定PID范围,循环遍历
	for (int i = 4; i < 100000; i += 4)
	{
		// 若通过PID能找到EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &proc)))
		{
			ULONG TableCode = *(ULONG*)((ULONG)proc + 0xF4);
			if (TableCode)
			{
				// char 拷贝至wchar,3环插入list前,用%大S来格式化,小s乱码
				_tcscpy_s(pProcessInfo->name, sizeof(pProcessInfo->name), PsGetProcessImageFileName(proc));
				pProcessInfo->PID = PsGetProcessId(proc);

				pProcessInfo++;// 指针后移
				ObDereferenceObject(proc);// 递减引用计数
			}
		}
	}
	// 4 数据传输-写入3环
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = (ULONG)pProcessInfo - (ULONG)pBuff;// 总共传输字节数
	return status;
}
NTSTATUS OnEnumModule1(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// 返回状态
	// 2 获取IO缓存区(二者共用
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// 若调试状态则下断
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 获取当前进程模块数
	//KdBreakPoint();
	ULONG ModuleCount = 0;
	ULONG ProcessCount = 0;
	PEPROCESS proc = NULL;
	int ProcIndex = *(int*)pBuff;// 当前进程
	// 设定PID范围,循环遍历
	for (int i = 4; i < 100000; i += 4)
	{
		// 若通过PID能找到EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &proc)))
		{
			ULONG TableCode = *(ULONG*)((ULONG)proc + 0xF4);
			if (TableCode)
			{


				// 找到相对应的进程
				if (ProcIndex == ProcessCount)
				{
					// 遍历模块
					// 1. 找到PEB(由于PEB在用户层空间,因此需要进程挂靠
					KAPC_STATE kapc_status = { 0 };
					KeStackAttachProcess(proc, &kapc_status);
					// 2. 找到PEB.Ldr(模块链表)
					struct _PEB* peb = PsGetProcessPeb(proc);
					if (peb != NULL)
					{
						__try {
							// 3. 遍历模块链表
							LDR_DATA_TABLE_ENTRY* pLdrEntry = (LDR_DATA_TABLE_ENTRY*)peb->Ldr->InLoadOrderModuleList.Flink;
							LDR_DATA_TABLE_ENTRY* pBegin = pLdrEntry;
							do
							{
								KdPrint(("\t%d BASE:%p SIZE:%06X %wZ\n",
									ModuleCount,
									pLdrEntry->DllBase,
									pLdrEntry->SizeOfImage,
									&pLdrEntry->FullDllName));

								ModuleCount++;
								// 找到下一个
								pLdrEntry = (LDR_DATA_TABLE_ENTRY*)pLdrEntry->InLoadOrderLinks.Flink;
							} while (pBegin != pLdrEntry);
						}
						__except (EXCEPTION_EXECUTE_HANDLER) {}
					}


					KeUnstackDetachProcess(&kapc_status);// 解除挂靠
					ObDereferenceObject(proc);// 递减引用计数
				}
				ProcessCount++;// 进程个数+1 	
			}
		}
	}

	// 4 数据传输-写入3环
	RtlCopyMemory(pBuff, &ModuleCount, sizeof(ModuleCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = sizeof(ModuleCount);// 总共传输字节数
	return status;
}
NTSTATUS OnEnumModule2(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// 返回状态
	// 2 获取IO缓存区(二者共用
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// 若调试状态则下断
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 获取当前进程模块数
	//KdBreakPoint();
	ULONG ModuleCount = 0;
	ULONG ProcessCount = 0;
	PEPROCESS proc = NULL;
	int ProcIndex = *(int*)pBuff;// 当前进程,先将缓冲区作输入用
	PMODULEINFO pModuleInfo = NULL;
	// 设定PID范围,循环遍历
	for (int i = 4; i < 100000; i += 4)
	{
		// 若通过PID能找到EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &proc)))
		{
			ULONG TableCode = *(ULONG*)((ULONG)proc + 0xF4);
			if (TableCode)
			{
				// 找到相对应的进程
				if (ProcIndex == ProcessCount)
				{
					// 遍历模块
					// 1. 找到PEB(由于PEB在用户层空间,因此需要进程挂靠
					KAPC_STATE kapc_status = { 0 };
					KeStackAttachProcess(proc, &kapc_status);
					// 2. 找到PEB.Ldr(模块链表)
					struct _PEB* peb = PsGetProcessPeb(proc);
					if (peb != NULL)
					{
						pModuleInfo = (PMODULEINFO)pBuff;// 再将缓冲区作输出用
						__try {
							// 3. 遍历模块链表
							LDR_DATA_TABLE_ENTRY* pLdrEntry = (LDR_DATA_TABLE_ENTRY*)peb->Ldr->InLoadOrderModuleList.Flink;
							LDR_DATA_TABLE_ENTRY* pBegin = pLdrEntry;
							do
							{
								KdPrint(("\t%d BASE:%p SIZE:%06X %wZ\n",
									ModuleCount,
									pLdrEntry->DllBase,
									pLdrEntry->SizeOfImage,
									&pLdrEntry->FullDllName));

								// 写入各字段
								_tcscpy_s(pModuleInfo->name, sizeof(pModuleInfo->name), pLdrEntry->FullDllName.Buffer);
								pModuleInfo->base = pLdrEntry->DllBase;
								pModuleInfo->size = pLdrEntry->SizeOfImage;

								pModuleInfo++;// 指针后移

								ModuleCount++;
								// 找到下一个
								pLdrEntry = (LDR_DATA_TABLE_ENTRY*)pLdrEntry->InLoadOrderLinks.Flink;
							} while (pBegin != pLdrEntry);
						}
						__except (EXCEPTION_EXECUTE_HANDLER) {}
					}


					KeUnstackDetachProcess(&kapc_status);// 解除挂靠
					ObDereferenceObject(proc);// 递减引用计数
				}
				ProcessCount++;// 进程个数+1 	
			}
		}
	}

	// 4 数据传输-写入3环
	//RtlCopyMemory(pBuff, &ModuleCount, sizeof(ModuleCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = (ULONG)pModuleInfo - (ULONG)pBuff;// 尾地址-首地址=传输大小
	return status;
}
NTSTATUS OnEnumThread1(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// 返回状态
	// 2 获取IO缓存区(二者共用
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// 若调试状态则下断
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 获取当前进程模块数
	//KdBreakPoint();
	ULONG ThreadCount = 0;
	ULONG ProcessCount = 0;
	PEPROCESS pEProcess = NULL;
	PETHREAD pEThread = NULL;
	int ProcIndex = *(int*)pBuff;// 当前进程
	// 设定PID范围,循环遍历
	for (int i = 4; i < 100000; i += 4)
	{
		// 若通过PID能找到EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &pEProcess)))
		{
			ULONG TableCode = *(ULONG*)((ULONG)pEProcess + 0xF4);
			if (TableCode)
			{
				// 找到相对应的进程
				if (ProcIndex == ProcessCount)
				{
					//KdBreakPoint();
					KdPrint(("\tPID:%d %s\n", (ULONG)PsGetProcessId(pEProcess), PsGetProcessImageFileName(pEProcess)));

					// 遍历线程
					for (ULONG j = 4; j < 0x25600; j += 4)
					{
						// 若通过TID能找到ETHREAD
						if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)j, &pEThread)))
						{
							// 获取线程所属进程,若相等则
							PEPROCESS proc = IoThreadToProcess(pEThread);
							if (pEProcess == proc)
							{
								KdPrint(("\t%d TID:%d\n", ThreadCount, (ULONG)PsGetThreadId(pEThread)));
								ThreadCount++;
							}
							ObDereferenceObject(pEThread);// 递减引用计数
						}
					}

					ObDereferenceObject(pEProcess);// 递减引用计数
				}
				ProcessCount++;// 进程个数+1 
			}
		}
	}
	// 4 数据传输-写入3环
	RtlCopyMemory(pBuff, &ThreadCount, sizeof(ThreadCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = sizeof(ThreadCount);// 总共传输字节数
	return status;
}
NTSTATUS OnEnumThread2(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// 返回状态
	// 2 获取IO缓存区(二者共用
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// 若调试状态则下断
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 获取当前进程模块数
	//KdBreakPoint();
	ULONG ThreadCount = 0;
	ULONG ProcessCount = 0;
	PEPROCESS pEProcess = NULL;
	PETHREAD pEThread = NULL;
	int ProcIndex = *(int*)pBuff;// 当前进程
	PTHREADINFO pThreadInfo = NULL;
	// 设定PID范围,循环遍历
	for (int i = 4; i < 1000; i += 4)
	{
		// 若通过PID能找到EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &pEProcess)))
		{
			ULONG TableCode = *(ULONG*)((ULONG)pEProcess + 0xF4);
			if (TableCode)
			{
				// 找到相对应的进程
				if (ProcIndex == ProcessCount)
				{
					pThreadInfo = (PTHREADINFO)pBuff;// 再将缓冲区作输出用
					//KdBreakPoint();
					KdPrint(("\tPID:%d %s\n", (ULONG)PsGetProcessId(pEProcess), PsGetProcessImageFileName(pEProcess)));

					// 遍历线程
					for (ULONG j = 4; j < 1000; j += 4)
					{
						// 若通过TID能找到ETHREAD
						if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)j, &pEThread)))
						{
							// 获取线程所属进程,若相等则
							PEPROCESS proc = IoThreadToProcess(pEThread);
							if (pEProcess == proc)
							{

								// 写入各字段
								pThreadInfo->TID = PsGetThreadId(pEThread);
								//pThreadInfo->OwnerPID = PsGetProcessId(pEProcess);
								pThreadInfo++;// 指针后移

								KdPrint(("\t%d TID:%d\n", ThreadCount, (ULONG)PsGetThreadId(pEThread)));
								ThreadCount++;
							}
							ObDereferenceObject(pEThread);// 递减引用计数
						}
					}

					ObDereferenceObject(pEProcess);// 递减引用计数
				}
				ProcessCount++;// 进程个数+1 
			}
		}
	}
	// 4 数据传输-写入3环
	//RtlCopyMemory(pBuff, &ThreadCount, sizeof(ThreadCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = (ULONG)pThreadInfo - (ULONG)pBuff;// 总共传输字节数
	return status;
}
NTSTATUS OnEnumIDT1(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// 返回状态
	// 2 获取IO缓存区(二者共用
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// 遍历IDT
	//KdBreakPoint();
	IDT_INFO SIDT = { 0,0,0 };
	PIDT_ENTRY pIDTEntry = NULL;
	ULONG uAddr = 0;
	// 获取IDT表地址
	_asm sidt SIDT;
	// 获取IDT表数组地址
	pIDTEntry = (PIDT_ENTRY)MAKELONG(SIDT.uLowIdtBase, SIDT.uHighIdtBase);
	// 获取IDT信息
	//ULONG IDTEntryCount = 0;
	PIDTINFO pIDTInfo = (PIDTINFO)pBuff;
	KdPrint(("---------------中断描述符表---------\n"));
	for (ULONG i = 0; i < 0x100; i++)
	{
		ULONG Idt_address = MAKELONG(pIDTEntry[i].uOffsetLow, pIDTEntry[i].uOffsetHigh);
		KdPrint(("addr: %08X, int: %d, selector: %d, GateType:%d, DPL: %d\n",
			Idt_address,// 中断地址
			i,// 中断号
			pIDTEntry[i].uSelector,// 段选择子
			pIDTEntry[i].GateType,//类型
			pIDTEntry[i].DPL//特权等级
			));
		pIDTInfo->addr = Idt_address;
		pIDTInfo->uSelector = pIDTEntry[i].uSelector;
		pIDTInfo->GateType = pIDTEntry[i].GateType;
		pIDTInfo->DPL = pIDTEntry[i].DPL;

		pIDTInfo++;// 指针后移

		//IDTEntryCount++;
	}

	// 4 数据传输-写入3环
	//RtlCopyMemory(pBuff, &IDTEntryCount, sizeof(IDTEntryCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information =(ULONG)pIDTInfo-(ULONG)pBuff;// 总共传输字节数
	return status;
}
NTSTATUS OnEnumGDT1(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// 返回状态
	// 2 获取IO缓存区(二者共用
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// 遍历GDT
	//KdBreakPoint();
	GDT_INFO SGDT = { 0,0,0 };
	PGDT_ENTRY pGDTEntry = NULL;
	ULONG uAddr = 0;
	// 获取GDT表地址
	_asm sgdt SGDT;
	// 获取GDT表数组地址
	pGDTEntry = (PGDT_ENTRY)MAKELONG(SGDT.uLowGdtBase, SGDT.uHighGdtBase);
	// 获取GDT信息
	//ULONG GDTEntryCount = 0;
	PGDTINFO pGDTInfo = (PGDTINFO)pBuff;
	KdPrint(("---------------中断描述符表---------\n"));
	for (ULONG i = 0; i < 0x100; i++)
	{
		ULONG Gdt_address = 0;
		Gdt_address = MAKELONG(pGDTEntry[i].Base16_31, pGDTEntry[i].Base0_7);
		Gdt_address = MAKELONG(Gdt_address, pGDTEntry[i].Base24_31);
		ULONG Gdt_limit = MAKELONG(pGDTEntry[i].Limit_0_15, pGDTEntry[i].Limit_16_19);
		// 打印
		KdPrint(("addr: %08X, limit: %d, P: %d, G:%d, S:%d,Type:%d,D/B:%d,DPL:%d\n",
			Gdt_address, Gdt_limit,
			pGDTEntry[i].P,
			pGDTEntry[i].G,
			pGDTEntry[i].S,
			pGDTEntry[i].Type,
			pGDTEntry[i].D_B,
			pGDTEntry[i].DPL
			));
		// 拷贝
		pGDTInfo->Base = Gdt_address;
		pGDTInfo->Limit = Gdt_limit;
		pGDTInfo->P = pGDTEntry[i].P;
		pGDTInfo->G = pGDTEntry[i].G;
		pGDTInfo->S = pGDTEntry[i].S;
		pGDTInfo->Type = pGDTEntry[i].Type;
		pGDTInfo->D_B = pGDTEntry[i].D_B;
		pGDTInfo->DPL = pGDTEntry[i].DPL;

		pGDTInfo++;// 指针后移

		//GDTEntryCount++;
	}

	// 4 数据传输-写入3环
	//RtlCopyMemory(pBuff, &GDTEntryCount, sizeof(GDTEntryCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = (ULONG)pGDTInfo - (ULONG)pBuff;// 总共传输字节数
	return status;
}
NTSTATUS OnHideDriver(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// 返回状态
	// 1 获取双向链表首地址
	PDRIVER_OBJECT pDriver = pDevice->DriverObject;// 设备对象归属的驱动对象
	PLDR_DATA_TABLE_ENTRY pLdr = pDriver->DriverSection;// 多条驱动信息构成的双向链表
	PLDR_DATA_TABLE_ENTRY pBegin = pLdr;// 链表首地址
	// 2 获取IO缓存区(二者共用
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;
	// 若调试状态则下断
#ifdef _DEBUG
	KdBreakPoint();
#endif
	// 3 获取驱动个数
	KdBreakPoint();
	ULONG driverCount = 0;
	int driverIndex = *(int*)pBuff;// 当前驱动
	__try
	{
		do
		{
			// 找到目标驱动
			if (driverIndex == driverCount)
			{
				KdPrint(("%d %08X | %06X | %wZ\n", driverCount, pLdr->DllBase, pLdr->SizeOfImage, &pLdr->FullDllName));

				// 修改Flink和Blink指针,来跳过要隐藏的驱动
				// (前 目标 后)三个,前指后,后指前,跳过中间的目标
				*((ULONG*)pLdr->InLoadOrderLinks.Blink) = (ULONG)pLdr->InLoadOrderLinks.Flink;
				pLdr->InLoadOrderLinks.Flink->Blink = pLdr->InLoadOrderLinks.Blink;
				// 避免造成随机性的BSoD(蓝屏
				pLdr->InLoadOrderLinks.Flink = (LIST_ENTRY*)&(pLdr->InLoadOrderLinks.Flink);
				pLdr->InLoadOrderLinks.Blink = (LIST_ENTRY*)&(pLdr->InLoadOrderLinks.Flink);

				break;
			}
			driverCount++;
			pLdr = (PLDR_DATA_TABLE_ENTRY)pLdr->InLoadOrderLinks.Flink;
		} while (pBegin != pLdr);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("Exception: 0x%08X\n", GetExceptionCode()));
	}
	// 4 数据传输-写入3环
	//RtlCopyMemory(pBuff, &driverCount, sizeof(driverCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = 0;// 总共传输字节数
	return status;
}
NTSTATUS OnHideProcess(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// 返回状态
	// 2 获取IO缓存区(二者共用
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// 若调试状态则下断
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 获取进程数
	//KdBreakPoint();
	int processIndex = *(int*)pBuff;// 目标进程
	ULONG ProcessCount = 0;
	PEPROCESS proc = NULL;
	// 设定PID范围,循环遍历
	for (int i = 4; i < 100000; i += 4)
	{
		// 若通过PID能找到EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &proc)))
		{
			ULONG TableCode = *(ULONG*)((ULONG)proc + 0xF4);
			if (TableCode)
			{


				// 找到要隐藏的目标进程
				if (processIndex == ProcessCount)
				{
					KdPrint(("%d : %s\n", ProcessCount, PsGetProcessImageFileName(proc)));

					// 获取进程对象内的当前活动进程链表
					LIST_ENTRY* pProcList = (LIST_ENTRY*)((ULONG)proc + 0xB8);

					// 修改Flink和Blink指针,来跳过要隐藏的驱动(前 目标 后)
					*((ULONG*)pProcList->Blink) = (ULONG)pProcList->Flink;//后指前
					pProcList->Flink->Blink = pProcList->Blink;//前指后
					// 避免造成随机性的BSoD(蓝屏
					pProcList->Flink = (LIST_ENTRY*)&(pProcList->Flink);
					pProcList->Blink = (LIST_ENTRY*)&(pProcList->Flink);

					break;

				}
				ProcessCount++;// 个数+1 

				ObDereferenceObject(proc);// 递减引用计数
			}

		}
	}
	// 4 数据传输-写入3环
	//RtlCopyMemory(pBuff, &ProcessCount, sizeof(ProcessCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = 0;// 总共传输字节数
	return status;
}
NTSTATUS OnKillProcess(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// 返回状态
	// 2 获取IO缓存区(二者共用
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// 若调试状态则下断
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 获取进程数
	//KdBreakPoint();
	int processIndex = *(int*)pBuff;// 目标进程
	ULONG ProcessCount = 0;
	PEPROCESS proc = NULL;
	// 设定PID范围,循环遍历
	for (int i = 4; i < 100000; i += 4)
	{
		// 若通过PID能找到EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &proc)))
		{
			ULONG TableCode = *(ULONG*)((ULONG)proc + 0xF4);
			if (TableCode)
			{
				// 找到要结束的目标进程
				if (processIndex == ProcessCount)
				{
					KdPrint(("%d : %s\n", ProcessCount, PsGetProcessImageFileName(proc)));

					// 结束进程
					HANDLE hProcess = NULL;
					OBJECT_ATTRIBUTES objAttribute = { sizeof(OBJECT_ATTRIBUTES) };
					CLIENT_ID clientID = { 0 };
					clientID.UniqueProcess = (HANDLE)PsGetProcessId(proc);
					clientID.UniqueThread = 0;
					ZwOpenProcess(&hProcess, 1, &objAttribute, &clientID);//获取进程句柄
					if (hProcess)
					{
						ZwTerminateProcess(hProcess, 0);
						ZwClose(hProcess);
					}

					break;

				}
				ProcessCount++;// 个数+1 

				ObDereferenceObject(proc);// 递减引用计数
			}


		}
	}
	// 4 数据传输-写入3环
	//RtlCopyMemory(pBuff, &ProcessCount, sizeof(ProcessCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = 0;// 总共传输字节数
	return status;
}

// 绑定控制码与派遣函数
typedef struct _DeivecIoCtrlhandler
{
	ULONG ctrl_code;
	NTSTATUS(*callback)(DEVICE_OBJECT *pDevice, IRP *pIrp);
}DeivecIoCtrlhandler;
DeivecIoCtrlhandler g_handler[] =
{
	 {enumDriver1 , OnEnumDriver1},
	 {enumDriver2 , OnEnumDriver2},
	 {enumProcess1 , OnEnumProcess1},
	 {enumProcess2 , OnEnumProcess2},
	 {enumThread1 , OnEnumThread1},
	 {enumThread2 , OnEnumThread2},
	 {enumModule1 , OnEnumModule1},
	 {enumModule2 , OnEnumModule2},
	 {enumIDT1 , OnEnumIDT1},
	 {enumGDT1 , OnEnumGDT1},
	 {HideDriver,OnHideDriver},
	 {HideProcess,OnHideProcess},
	 {KillProcess,OnKillProcess},
};

// 全局变量
LDR_DATA_TABLE_ENTRY* pLdr = NULL;
LDR_DATA_TABLE_ENTRY* pBegin = NULL;
int driverCount = 0;

// 卸载函数
void OnUnload(DRIVER_OBJECT* object)
{
	KdPrint(("驱动被卸载\n"));
	// 卸载设备
	IoDeleteDevice(object->DeviceObject);
	// 删除符号链接
	UNICODE_STRING symName = RTL_CONSTANT_STRING(NAME_SYMBOL);
	IoDeleteSymbolicLink(&symName);
}
// 派遣函数
NTSTATUS OnCreate(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	pDevice;
	KdPrint(("设备被创建\n"));
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS OnClose(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	pDevice;
	KdPrint(("设备被关闭\n"));
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS OnDeviceIoControl(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	pDevice;
	//DbgBreakPoint();
	// 1 获取IO缓存区(二者共用
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;
	// 2 获取IO栈及相关信息
	IO_STACK_LOCATION* pIoStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG uInputLen = pIoStack->Parameters.DeviceIoControl.InputBufferLength;//输入缓冲区字节数
	ULONG uOutputLen = pIoStack->Parameters.DeviceIoControl.OutputBufferLength;//输出缓冲区字节数
	ULONG uCtrlCode = pIoStack->Parameters.DeviceIoControl.IoControlCode;//控制码
	KdPrint(("控制码:%08X 输入长度:%d 输出长度:%d\n", uCtrlCode, uInputLen, uOutputLen));

	// 3 调用相应的派遣函数
	for (int i = 0; i < _countof(g_handler); ++i)
	{
		if (g_handler[i].ctrl_code == uCtrlCode)
		{
			g_handler[i].callback(pDevice, pIrp);
		}
	}


	//// 4 根据控制码来完成相应操作
	//switch (uCtrlCode)
	//{
	//case readProcessMemory:
	//{
	//	// 获取3环信息
	//	ULONG* pPid = (ULONG*)pBuff;
	//	// 在0环处理
	//	KdPrint(("[内核层]读取进程内存的请求\n"));
	//	KdPrint(("pid=%d\n", *pPid));
	//	// 输出至3环
	//	RtlCopyMemory(pBuff, _TEXT("aaaaaaaaa"), 20);// 输出内容
	//	pIrp->IoStatus.Information = 20;// 输出的字节数
	//	break;
	//}
	//case writeProcessMemory:
	//{
	//	struct _ProcessInfo
	//	{
	//		ULONG dwPid;
	//		void* address;
	//		char buff[1000];
	//		int buffSize;
	//	};
	//	// 获取3环信息
	//	struct _ProcessInfo* pProcInfo = (struct _ProcessInfo*)pBuff;
	//	// 在0环处理
	//	KdPrint(("[内核层]写进程内存的请求\n"));
	//	KdPrint(("pid=%d address=%p buffsize=%d\n",
	//		pProcInfo->dwPid,
	//		pProcInfo->address,
	//		pProcInfo->buffSize));
	//	// 输出至3环
	//	RtlCopyMemory(pBuff, _TEXT("bbbbbbbbbbb"), 20);
	//	pIrp->IoStatus.Information = 20;
	//	break;
	//}
	//case listDriver:
	//{
	//	int count = 1;
	//	DRIVERINFO driverInfo = { 0 };
	//	KdPrint(("加载基址 | 大  小 | 路径\n"));
	//	__try 
	//	{
	//		do
	//		{
	//			KdPrint(("%d %08X | %06X | %wZ\n",count,pLdr->DllBase,pLdr->SizeOfImage,&pLdr->FullDllName));
	//			////依次将信息赋值，并传递
	//			//RtlCopyMemory(driverInfo.name, pLdr->FullDllName.Buffer, pLdr->FullDllName.Length);
	//			//driverInfo.size = pLdr->SizeOfImage;
	//			//driverInfo.base = pLdr->DllBase;
	//			////设置缓冲区返回内容
	//			//RtlCopyMemory(pBuff, (PVOID)&driverInfo, sizeof(driverInfo));
	//			//pBuff = pBuff + sizeof(driverInfo);
	//			
	//			count++;
	//			pLdr = (LDR_DATA_TABLE_ENTRY*)(pLdr->InLoadOrderLinks.Flink);
	//		} while (pBegin != pLdr);
	//	}
	//	__except (EXCEPTION_EXECUTE_HANDLER) 
	//	{
	//		KdPrint(("出现异常:%08x", GetExceptionCode()));
	//	}
	//	//RtlCopyMemory(pBuff, _TEXT("123123"), 20);// 输出内容
	//	driverCount = count - 1;
	//	pIrp->IoStatus.Information = driverCount;// 输出的字节数
	//	
	//	break;
	//}
	//case listDriver2:
	//{
	//	DbgBreakPoint();
	//	int index = *(int*)pBuff;
	//	int count = 0;
	//	DRIVERINFO driverInfo = { 0 };
	//	__try
	//	{
	//		do
	//		{
	//			if (index == count)
	//			{
	//				//依次将信息赋值，并传递
	//				RtlCopyMemory(driverInfo.name, pLdr->FullDllName.Buffer, pLdr->FullDllName.Length);
	//				driverInfo.size = pLdr->SizeOfImage;
	//				driverInfo.base = pLdr->DllBase;
	//				//设置缓冲区返回内容
	//				RtlCopyMemory(pBuff, &driverInfo, sizeof(DRIVERINFO));
	//				break;
	//			}
	//			count++;
	//			pLdr = (LDR_DATA_TABLE_ENTRY*)(pLdr->InLoadOrderLinks.Flink);
	//		} while (pBegin != pLdr);
	//	}
	//	__except (EXCEPTION_EXECUTE_HANDLER)
	//	{
	//		KdPrint(("出现异常:%08x", GetExceptionCode()));
	//	}
	//	pIrp->IoStatus.Information = sizeof(DRIVERINFO);// 输出的字节数
	//	break;
	//}
	//case enumDriver1:
	//{
	//}
	//case enumDriver2:
	//{
	//}
	//default:
	//	break;
	//}


	// 5 设置IRP完成状态
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

// 入口
NTSTATUS DriverEntry(DRIVER_OBJECT* pDriverObj, UNICODE_STRING* path)
{
	path;
	KdPrint(("驱动被加载\n"));
	NTSTATUS status = STATUS_SUCCESS;
	// 1 绑定卸载函数
	pDriverObj->DriverUnload = &OnUnload;
	// 2 创建设备对象
	UNICODE_STRING devName = RTL_CONSTANT_STRING(NAME_DEVICE);
	DEVICE_OBJECT* pDevice = NULL;// 保存新设备对象的指针.
	status = IoCreateDevice(pDriverObj, 0, &devName, FILE_DEVICE_UNKNOWN, 0, 0, &pDevice);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("创建设备失败,错误码:%08X\n", status));
		return status;
	}
	pDevice->Flags |= DO_BUFFERED_IO;// 通讯方式
	// 3 绑定符号链接
	UNICODE_STRING symbolName = RTL_CONSTANT_STRING(NAME_SYMBOL);
	IoCreateSymbolicLink(&symbolName, &devName);
	// 4 绑定派遣函数
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = &OnCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = &OnClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &OnDeviceIoControl;


	//pLdr = (LDR_DATA_TABLE_ENTRY*)pDriverObj->DriverSection;
	//pBegin = pLdr;

	return status;
}


