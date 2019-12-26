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
typedef struct _FILEINFO
{
	TCHAR fileName[260];
	ULONGLONG size;
	ULONG attribute;
	ULONGLONG createTime;
	ULONGLONG changeTime;
}FILEINFO, *PFILEINFO;
typedef struct _SSDTINFO
{
	ULONG funcAddr;
	//ULONG paramCount;
}SSDTINFO, *PSSDTINFO;

typedef struct _IDT_INFO
{
	UINT16 uIdtLimit;
	UINT16 uLowIdtBase;
	UINT16 uHighIdtBase;
}IDT_INFO, *PIDT_INFO;
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

#pragma pack(1)
typedef  struct  _KSYSTEM_SERVICE_TABLE
{
	PULONG  ServiceTableBase;   //函数地址表的首地址
	PULONG  ServiceCounterTableBase;// 函数表中每个函数被调用的次数
	ULONG   NumberOfService;// 服务函数的个数, NumberOfService * 4 就是整个地址表的大小
	UCHAR*   ParamTableBase; // 参数个数表首地址
} KSYSTEM_SERVICE_TABLE, *PKSYSTEM_SERVICE_TABLE;
typedef  struct  _KSERVICE_TABLE_DESCRIPTOR
{
	KSYSTEM_SERVICE_TABLE   ntoskrnl;// ntoskrnl.exe的服务函数，即SSDT
	KSYSTEM_SERVICE_TABLE   win32k; // win32k.sys的服务函数(GDI32.dll/User32.dll 的内核支持)，即ShadowSSDT
	KSYSTEM_SERVICE_TABLE   notUsed1; // 不使用
	KSYSTEM_SERVICE_TABLE   notUsed2; // 不使用
}KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;


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
	enumFile1 = MYCTLCODE(13),
	enumFile2 = MYCTLCODE(14),
	deleteFile = MYCTLCODE(15),
	enumSSDT1 = MYCTLCODE(16),
	enumSSDT2 = MYCTLCODE(17),
	hookSysEnter = MYCTLCODE(18),// 3环程序将自身PID发送至0环,hook用到
}MyCtlCode;

// HOOK-SYSENTER相关
//CHAR* PsGetProcessImageFileName(PEPROCESS*);
ULONG_PTR    g_oldKiFastCallEntery;
ULONG        g_uPid = 2840; // 需要保护的进程ID, 这个PID可以通过内核通讯来修改.
void _declspec(naked) MyKiFastCallEntry()
{
	/**
	  * 本函数是从用户层直接切换进来的.
	  * 在本函数中,有以下信息可以使用:
	  * 1. eax保存的是调用号
	  * 2. edx保存着用户层的栈顶,且用户层的栈顶布局为:
	  *        edx+0 [ 返回地址1 ]
	  *        edx+4 [ 返回地址2 ]
	  *        edx+8 [ 形   参1 ]
	  *        edx+C [ 形   参2 ]
	  * 3. 要HOOK的API是 OpenProcess,其调用号和参数信息为:
	  *    调用号 - 0xBE
	  *    函数参数 -
	  *    NtOpenProcess(
	  *  [edx+08h] PHANDLE            ProcessHandle,// 输出参数,进程句柄
	  *  [edx+0Ch] ACCESS_MASK        DesiredAccess,// 打开的权限
	  *  [edx+10h] POBJECT_ATTRIBUTES ObjectAttributes,// 对象属性,无用
	  *  [edx+14h] PCLIENT_ID         ClientId         // 进程ID和线程ID的结构体
	  *  最后一个参数的结构体原型为:
	  *  typedef struct _CLIENT_ID
	  *  {
	  *        PVOID UniqueProcess;// 进程ID
	  *     PVOID UniqueThread; // 线程ID(在这个函数中用不到)
	  *  } CLIENT_ID, *PCLIENT_ID;
	  *
	  * HOOK 步骤:
	  * 1. 检查调用号是不是0xBE(ZwOpenProcess)
	  * 2. 检查进程ID是不是要保护的进程的ID
	  * 3. 如果是,则将进程ID改为0,再调用原来的函数,这样一来,即使功能被执行,
	  *    也无法打开进程, 或者将访问权限设置为0,同样也能让进程无法被打开.
	  * 4. 如果不是,则调用原来的KiFastCallEntry函数
	  */



	_asm
	{
		;// 1. 检查调用号
		cmp eax, 0xBE;
		jne _DONE; // 调用号不是0xBE,执行第4步

		;// 2. 检查进程ID是不是要保护的进程的ID
		push eax; // 备份寄存器

		;// 2. 获取参数(进程ID)
		mov eax, [edx + 0x14];// eax保存的是PCLIENT_ID
		mov eax, [eax];// eax保存的是PCLIENT_ID->UniqueProcess

		;// 3. 判断是不是要保护的进程ID
		cmp eax, [g_uPid];
		pop eax;// 恢复寄存器
		jne _DONE;// 不是要保护的进程就跳转

		;// 3.1 是的话就该调用参数,让后续函数调用失败.
		mov[edx + 0xC], 0; // 将访问权限设置为0

	_DONE:
		; // 4. 调用原来的KiFastCallEntry
		jmp g_oldKiFastCallEntery;
	}
}
void _declspec(naked) installSysenterHook()
{
	_asm
	{
		push edx;
		push eax;
		push ecx;

		;// 备份原始函数
		mov ecx, 0x176;//SYSENTER_EIP_MSR寄存器的编号.保存着KiFastCallEntry的地址
		rdmsr; // // 指令使用ecx寄存器的值作为MSR寄存器组的编号,将这个编号的寄存器中的值读取到edx:eax
		mov[g_oldKiFastCallEntery], eax;// 将地址保存到全局变量中.

		;// 将新的函数设置进去.
		mov eax, MyKiFastCallEntry;
		xor edx, edx;
		wrmsr; // 指令使用ecx寄存器的值作为MSR寄存器组的编号,将edx:eax写入到这个编号的寄存器中.
		pop ecx;
		pop eax;
		pop edx;
		ret;
	}
}
void uninstallSysenterHook()
{
	_asm
	{
		push edx;
		push eax;
		push ecx;
		;// 将新的函数设置进去.
		mov eax, [g_oldKiFastCallEntery];
		xor edx, edx;
		mov ecx, 0x176;
		wrmsr; // 指令使用ecx寄存器的值作为MSR寄存器组的编号,将edx:eax写入到这个编号的寄存器中.
		pop ecx;
		pop eax;
		pop edx;
	}
}


// 工具函数
NTSTATUS FindFirstFile(const WCHAR* pszPath, HANDLE* phDir, FILE_BOTH_DIR_INFORMATION* pFileInfo, int nInfoSize)
{
	NTSTATUS status = STATUS_SUCCESS;
	// 1. 打开文件夹,得到文件夹的文件句柄
	HANDLE hDir = NULL;
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING path;
	RtlInitUnicodeString(&path, pszPath);

	InitializeObjectAttributes(
		&oa,/*要初始化的对象属性结构体*/
		&path,/*文件路径*/
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,/*属性:路径不区分大小写,打开的句柄是内核句柄*/
		NULL,
		NULL);
	IO_STATUS_BLOCK isb = { 0 };
	status = ZwCreateFile(
		&hDir,/*输出的文件句柄*/
		GENERIC_READ,
		&oa,/*对象属性,需要提前将文件夹路径初始化进去*/
		&isb,
		NULL,/*文件预分配大小*/
		FILE_ATTRIBUTE_NORMAL,/*文件属性*/
		FILE_SHARE_READ,/*共享方式*/
		FILE_OPEN_IF,/*创建描述: 存在则打开*/
		FILE_DIRECTORY_FILE,/*创建选项: 目录文件*/
		NULL,
		0);

	if (!NT_SUCCESS(isb.Status)) {
		return isb.Status;
	}

	// 2. 通过文件夹的文件句柄查询文件夹下的文件信息.
	status = ZwQueryDirectoryFile(
		hDir,
		NULL,/*用于异步IO*/
		NULL,
		NULL,
		&isb,
		pFileInfo,/*保存文件信息的缓冲区*/
		nInfoSize,/*缓冲区的字节数.*/
		FileBothDirectoryInformation,/*要获取的信息的类型*/
		TRUE,/*是否只返回一个文件信息*/
		NULL,/*用于过滤文件的表达式: *.txt*/
		TRUE/*是否重新开始扫描*/
	);
	if (!NT_SUCCESS(isb.Status)) {
		return isb.Status;
	}
	// 传出文件句柄
	*phDir = hDir;
	return STATUS_SUCCESS;
}
NTSTATUS FindNextFile(HANDLE hDir, FILE_BOTH_DIR_INFORMATION* pFileInfo, int nInfoSize)
{
	IO_STATUS_BLOCK isb = { 0 };
	ZwQueryDirectoryFile(
		hDir,
		NULL,/*用于异步IO*/
		NULL,
		NULL,
		&isb,
		pFileInfo,/*保存文件信息的缓冲区*/
		nInfoSize,/*缓冲区的字节数.*/
		FileBothDirectoryInformation,/*要获取的信息的类型*/
		TRUE,/*是否只返回一个文件信息*/
		NULL,/*用于过滤文件的表达式: *.txt*/
		FALSE/*是否重新开始扫描*/
	);
	return isb.Status;
}
LONG GetFunticonAddr(PKSYSTEM_SERVICE_TABLE KeServiceDescriptorTable, LONG lgSsdtIndex)
{
	LONG lgSsdtAddr = 0;	//获取SSDT表的基址	
	lgSsdtAddr = (LONG)KeServiceDescriptorTable->ServiceTableBase;
	PLONG plgSsdtFunAddr = 0; 	//获取内核函数的地址指针	
	plgSsdtFunAddr = (PLONG)(lgSsdtAddr + lgSsdtIndex * 4); 	//返回内核函数的地址	
	return (*plgSsdtFunAddr);
}

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
	pIrp->IoStatus.Information = (ULONG)pIDTInfo - (ULONG)pBuff;// 总共传输字节数
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
NTSTATUS OnEnumFile1(DEVICE_OBJECT *pDevice, IRP *pIrp)
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

	// 遍历文件
	//KdBreakPoint();
	ULONG fileCount = 0;
	HANDLE hDir = NULL;
	char buff[sizeof(FILE_BOTH_DIR_INFORMATION) + 266 * 2];
	FILE_BOTH_DIR_INFORMATION* pFileInfo = (FILE_BOTH_DIR_INFORMATION*)buff;
	status = FindFirstFile(_TEXT("\\??\\C:\\"), &hDir, pFileInfo, sizeof(buff));
	if (!NT_SUCCESS(status))
	{
		KdPrint(("查找第一个文件失败:%08X\n", status));
		return status;
	}
	do
	{
		// 处理Filename字段,防止乱码
		UNICODE_STRING uniName;
		TCHAR name[1024] = { 0 };
		RtlZeroMemory(name, 1024);
		RtlCopyMemory(name, pFileInfo->FileName, pFileInfo->FileNameLength);// 输出内容
		RtlInitUnicodeString(&uniName, name);
		// 打印信息
		KdPrint(("index:%d,文件名:%wZ,占用空间:%lld,属性值:%d,创建时间:%u, 修改时间:%llu\n", fileCount, &uniName, pFileInfo->AllocationSize.QuadPart, pFileInfo->FileAttributes, pFileInfo->CreationTime, pFileInfo->ChangeTime.QuadPart));
		// 个数+1
		fileCount++;
	} while (STATUS_SUCCESS == FindNextFile(hDir, pFileInfo, sizeof(buff)));


	// 4 数据传输-写入3环
	RtlCopyMemory(pBuff, &fileCount, sizeof(fileCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = sizeof(fileCount);// 总共传输字节数
	return status;
}
NTSTATUS OnEnumFile2(DEVICE_OBJECT *pDevice, IRP *pIrp)
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

	// 遍历文件
	//KdBreakPoint();
	PFILEINFO pFileInformation = (PFILEINFO)pBuff;
	ULONG fileCount = 0;
	HANDLE hDir = NULL;
	char buff[sizeof(FILE_BOTH_DIR_INFORMATION) + 266 * 2];
	FILE_BOTH_DIR_INFORMATION* pFileInfo = (FILE_BOTH_DIR_INFORMATION*)buff;
	status = FindFirstFile(_TEXT("\\??\\C:\\"), &hDir, pFileInfo, sizeof(buff));
	if (!NT_SUCCESS(status))
	{
		KdPrint(("查找第一个文件失败:%08X\n", status));
		return status;
	}
	do
	{
		// 处理Filename字段,防止乱码
		UNICODE_STRING uniName;
		TCHAR name[1024] = { 0 };
		RtlZeroMemory(name, 1024);
		RtlCopyMemory(name, pFileInfo->FileName, pFileInfo->FileNameLength);// 输出内容
		RtlInitUnicodeString(&uniName, name);

		KdPrint(("index:%d,文件名:%wZ,占用空间:%lld,属性值:%d,创建时间:%llu, 修改时间:%llu\n", fileCount, &uniName, pFileInfo->AllocationSize.QuadPart, pFileInfo->FileAttributes, pFileInfo->CreationTime.QuadPart, pFileInfo->ChangeTime.QuadPart));
		fileCount++;

		_tcscpy_s(pFileInformation->fileName, sizeof(pFileInformation->fileName), uniName.Buffer);
		pFileInformation->attribute = pFileInfo->FileAttributes;
		pFileInformation->size = pFileInfo->AllocationSize.QuadPart;
		pFileInformation->createTime = pFileInfo->CreationTime.QuadPart;
		pFileInformation->changeTime = pFileInfo->ChangeTime.QuadPart;

		pFileInformation++;// 指针后移


	} while (STATUS_SUCCESS == FindNextFile(hDir, pFileInfo, sizeof(buff)));


	// 4 数据传输-写入3环
	//RtlCopyMemory(pBuff, &fileCount, sizeof(fileCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = (ULONG)pFileInformation - (ULONG)pBuff;// 总共传输字节数
	return status;
}
NTSTATUS OnDeleteFile(DEVICE_OBJECT *pDevice, IRP *pIrp)
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

	// 遍历文件
	KdBreakPoint();
	int fileIndex = *(int*)pBuff;// 待删除文件索引
	ULONG fileCount = 0;
	HANDLE hDir = NULL;
	char buff[sizeof(FILE_BOTH_DIR_INFORMATION) + 266 * 2];
	FILE_BOTH_DIR_INFORMATION* pFileInfo = (FILE_BOTH_DIR_INFORMATION*)buff;
	status = FindFirstFile(_TEXT("\\??\\C:\\"), &hDir, pFileInfo, sizeof(buff));
	if (!NT_SUCCESS(status))
	{
		KdPrint(("查找第一个文件失败:%08X\n", status));
		return status;
	}
	do
	{

		// 找到目标驱动
		if (fileIndex == fileCount)
		{
			// 处理Filename字段,防止乱码
			const UNICODE_STRING uniName;
			TCHAR name[1024] = { 0 };
			RtlZeroMemory(name, 1024);
			RtlCopyMemory(name, pFileInfo->FileName, pFileInfo->FileNameLength);// 输出内容
			RtlInitUnicodeString(&uniName, name);
			//RtlInitEmptyUnicodeString(&uniName, name,1024);
			// 打印信息
			KdPrint(("index:%d,文件名:%wZ\n", fileCount, &uniName));


			// 开始删除文件
			UNICODE_STRING path;
			//RtlInitEmptyUnicodeString(&path, _TEXT("\\??\\C:\\"), 2048);
			RtlInitUnicodeString(&path, _TEXT("\\??\\C:\\新建文本文档.txt"));
			//RtlInitUnicodeString(&path, _TEXT("\\??\\C:\\"));
			//RtlAppendUnicodeStringToString(&path, &uniName);
			KdPrint(("%wZ\n",&path));
			// 1. 初始化OBJECT_ATTRIBUTES的内容
			OBJECT_ATTRIBUTES objAttrib = { 0 };
			ULONG  ulAttributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
			InitializeObjectAttributes(&objAttrib,&path,ulAttributes,NULL,NULL);
			// 2. 删除指定文件/文件夹
			ZwDeleteFile(&objAttrib);


			break;
		}
		// 个数+1
		fileCount++;
	} while (STATUS_SUCCESS == FindNextFile(hDir, pFileInfo, sizeof(buff)));


	// 4 数据传输-写入3环
	//RtlCopyMemory(pBuff, &fileCount, sizeof(fileCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = 0;// 总共传输字节数
	return status;
}
NTSTATUS OnEnumSSDT1(DEVICE_OBJECT *pDevice, IRP *pIrp)
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

	// 3 获取驱动个数
	//KdBreakPoint();
	ULONG SSDTCount = 0;

	// 获取系统服务描述符表
	PETHREAD* pCurThread = PsGetCurrentThread();
	KSERVICE_TABLE_DESCRIPTOR * pServiceTable = (KSERVICE_TABLE_DESCRIPTOR*)
		(*(ULONG*)((ULONG_PTR)pCurThread + 0xBC));
	SSDTCount = pServiceTable->ntoskrnl.NumberOfService;// SSDT中函数个数
	// 4 数据传输-写入3环
	RtlCopyMemory(pBuff, &SSDTCount, sizeof(SSDTCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = sizeof(SSDTCount);// 总共传输字节数
	return status;
}
NTSTATUS OnEnumSSDT2(DEVICE_OBJECT *pDevice, IRP *pIrp)
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

	// 3 获取驱动个数
	ULONG SSDTCount = 0;
	PSSDTINFO pSSDTInfo = (PSSDTINFO)pBuff;
	// 获取系统服务描述符表
	PETHREAD* pCurThread = PsGetCurrentThread();
	KSERVICE_TABLE_DESCRIPTOR * pServiceTable = (KSERVICE_TABLE_DESCRIPTOR*)
		(*(ULONG*)((ULONG_PTR)pCurThread + 0xBC));
	SSDTCount = pServiceTable->ntoskrnl.NumberOfService;// SSDT中函数个数
	for (int i = 0; i < SSDTCount; i++)
	{
		pSSDTInfo->funcAddr = GetFunticonAddr(&pServiceTable->ntoskrnl, i);

		pSSDTInfo++;
	}

	// 4 数据传输-写入3环
	//RtlCopyMemory(pBuff, &SSDTCount, sizeof(SSDTCount));//内存拷贝
	pIrp->IoStatus.Status = status;// 完成状态
	pIrp->IoStatus.Information = (ULONG)pSSDTInfo-(ULONG)pBuff;// 总共传输字节数
	return status;
}
NTSTATUS OnHookSysEnter(DEVICE_OBJECT *pDevice, IRP *pIrp)
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
	// 3 安装hook
	KdBreakPoint();
	g_uPid = *(int*)pBuff;//获取PID
	installSysenterHook();
	KdPrint(("%d\n", g_uPid));
	// 4 数据传输-写入3环
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
	 {enumFile1,OnEnumFile1},
	 {enumFile2,OnEnumFile2},
	 {deleteFile,OnDeleteFile},
	 {enumSSDT1,OnEnumSSDT1},
	 {enumSSDT2,OnEnumSSDT2},
	 {hookSysEnter,OnHookSysEnter},

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
	// 卸载HOOK
	uninstallSysenterHook();
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

	// 安装HOOK
	//installSysenterHook();

	return status;
}