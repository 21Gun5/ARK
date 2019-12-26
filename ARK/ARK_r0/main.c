#include <ntifs.h>
#include <ntddk.h>
#include <stdlib.h>
#include <tchar.h>
#include <wchar.h>




// �豸\����������
#define NAME_DEVICE L"\\Device\\deviceARK"
#define NAME_SYMBOL L"\\DosDevices\\deviceARK"

#define MAKELONG(a,b) ((LONG)(((UINT16)(((DWORD_PTR)(a))&0xffff)) | ((ULONG)((UINT16)(((DWORD_PTR)(b))& 0xffff)))<<16))

// ������������ 
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
	PULONG  ServiceTableBase;   //������ַ����׵�ַ
	PULONG  ServiceCounterTableBase;// ��������ÿ�����������õĴ���
	ULONG   NumberOfService;// �������ĸ���, NumberOfService * 4 ����������ַ��Ĵ�С
	UCHAR*   ParamTableBase; // �����������׵�ַ
} KSYSTEM_SERVICE_TABLE, *PKSYSTEM_SERVICE_TABLE;
typedef  struct  _KSERVICE_TABLE_DESCRIPTOR
{
	KSYSTEM_SERVICE_TABLE   ntoskrnl;// ntoskrnl.exe�ķ���������SSDT
	KSYSTEM_SERVICE_TABLE   win32k; // win32k.sys�ķ�����(GDI32.dll/User32.dll ���ں�֧��)����ShadowSSDT
	KSYSTEM_SERVICE_TABLE   notUsed1; // ��ʹ��
	KSYSTEM_SERVICE_TABLE   notUsed2; // ��ʹ��
}KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;


// �Զ��������
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
	hookSysEnter = MYCTLCODE(18),// 3����������PID������0��,hook�õ�
}MyCtlCode;

// HOOK-SYSENTER���
//CHAR* PsGetProcessImageFileName(PEPROCESS*);
ULONG_PTR    g_oldKiFastCallEntery;
ULONG        g_uPid = 2840; // ��Ҫ�����Ľ���ID, ���PID����ͨ���ں�ͨѶ���޸�.
void _declspec(naked) MyKiFastCallEntry()
{
	/**
	  * �������Ǵ��û���ֱ���л�������.
	  * �ڱ�������,��������Ϣ����ʹ��:
	  * 1. eax������ǵ��ú�
	  * 2. edx�������û����ջ��,���û����ջ������Ϊ:
	  *        edx+0 [ ���ص�ַ1 ]
	  *        edx+4 [ ���ص�ַ2 ]
	  *        edx+8 [ ��   ��1 ]
	  *        edx+C [ ��   ��2 ]
	  * 3. ҪHOOK��API�� OpenProcess,����úźͲ�����ϢΪ:
	  *    ���ú� - 0xBE
	  *    �������� -
	  *    NtOpenProcess(
	  *  [edx+08h] PHANDLE            ProcessHandle,// �������,���̾��
	  *  [edx+0Ch] ACCESS_MASK        DesiredAccess,// �򿪵�Ȩ��
	  *  [edx+10h] POBJECT_ATTRIBUTES ObjectAttributes,// ��������,����
	  *  [edx+14h] PCLIENT_ID         ClientId         // ����ID���߳�ID�Ľṹ��
	  *  ���һ�������Ľṹ��ԭ��Ϊ:
	  *  typedef struct _CLIENT_ID
	  *  {
	  *        PVOID UniqueProcess;// ����ID
	  *     PVOID UniqueThread; // �߳�ID(������������ò���)
	  *  } CLIENT_ID, *PCLIENT_ID;
	  *
	  * HOOK ����:
	  * 1. �����ú��ǲ���0xBE(ZwOpenProcess)
	  * 2. ������ID�ǲ���Ҫ�����Ľ��̵�ID
	  * 3. �����,�򽫽���ID��Ϊ0,�ٵ���ԭ���ĺ���,����һ��,��ʹ���ܱ�ִ��,
	  *    Ҳ�޷��򿪽���, ���߽�����Ȩ������Ϊ0,ͬ��Ҳ���ý����޷�����.
	  * 4. �������,�����ԭ����KiFastCallEntry����
	  */



	_asm
	{
		;// 1. �����ú�
		cmp eax, 0xBE;
		jne _DONE; // ���úŲ���0xBE,ִ�е�4��

		;// 2. ������ID�ǲ���Ҫ�����Ľ��̵�ID
		push eax; // ���ݼĴ���

		;// 2. ��ȡ����(����ID)
		mov eax, [edx + 0x14];// eax�������PCLIENT_ID
		mov eax, [eax];// eax�������PCLIENT_ID->UniqueProcess

		;// 3. �ж��ǲ���Ҫ�����Ľ���ID
		cmp eax, [g_uPid];
		pop eax;// �ָ��Ĵ���
		jne _DONE;// ����Ҫ�����Ľ��̾���ת

		;// 3.1 �ǵĻ��͸õ��ò���,�ú�����������ʧ��.
		mov[edx + 0xC], 0; // ������Ȩ������Ϊ0

	_DONE:
		; // 4. ����ԭ����KiFastCallEntry
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

		;// ����ԭʼ����
		mov ecx, 0x176;//SYSENTER_EIP_MSR�Ĵ����ı��.������KiFastCallEntry�ĵ�ַ
		rdmsr; // // ָ��ʹ��ecx�Ĵ�����ֵ��ΪMSR�Ĵ�����ı��,�������ŵļĴ����е�ֵ��ȡ��edx:eax
		mov[g_oldKiFastCallEntery], eax;// ����ַ���浽ȫ�ֱ�����.

		;// ���µĺ������ý�ȥ.
		mov eax, MyKiFastCallEntry;
		xor edx, edx;
		wrmsr; // ָ��ʹ��ecx�Ĵ�����ֵ��ΪMSR�Ĵ�����ı��,��edx:eaxд�뵽�����ŵļĴ�����.
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
		;// ���µĺ������ý�ȥ.
		mov eax, [g_oldKiFastCallEntery];
		xor edx, edx;
		mov ecx, 0x176;
		wrmsr; // ָ��ʹ��ecx�Ĵ�����ֵ��ΪMSR�Ĵ�����ı��,��edx:eaxд�뵽�����ŵļĴ�����.
		pop ecx;
		pop eax;
		pop edx;
	}
}


// ���ߺ���
NTSTATUS FindFirstFile(const WCHAR* pszPath, HANDLE* phDir, FILE_BOTH_DIR_INFORMATION* pFileInfo, int nInfoSize)
{
	NTSTATUS status = STATUS_SUCCESS;
	// 1. ���ļ���,�õ��ļ��е��ļ����
	HANDLE hDir = NULL;
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING path;
	RtlInitUnicodeString(&path, pszPath);

	InitializeObjectAttributes(
		&oa,/*Ҫ��ʼ���Ķ������Խṹ��*/
		&path,/*�ļ�·��*/
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,/*����:·�������ִ�Сд,�򿪵ľ�����ں˾��*/
		NULL,
		NULL);
	IO_STATUS_BLOCK isb = { 0 };
	status = ZwCreateFile(
		&hDir,/*������ļ����*/
		GENERIC_READ,
		&oa,/*��������,��Ҫ��ǰ���ļ���·����ʼ����ȥ*/
		&isb,
		NULL,/*�ļ�Ԥ�����С*/
		FILE_ATTRIBUTE_NORMAL,/*�ļ�����*/
		FILE_SHARE_READ,/*����ʽ*/
		FILE_OPEN_IF,/*��������: �������*/
		FILE_DIRECTORY_FILE,/*����ѡ��: Ŀ¼�ļ�*/
		NULL,
		0);

	if (!NT_SUCCESS(isb.Status)) {
		return isb.Status;
	}

	// 2. ͨ���ļ��е��ļ������ѯ�ļ����µ��ļ���Ϣ.
	status = ZwQueryDirectoryFile(
		hDir,
		NULL,/*�����첽IO*/
		NULL,
		NULL,
		&isb,
		pFileInfo,/*�����ļ���Ϣ�Ļ�����*/
		nInfoSize,/*���������ֽ���.*/
		FileBothDirectoryInformation,/*Ҫ��ȡ����Ϣ������*/
		TRUE,/*�Ƿ�ֻ����һ���ļ���Ϣ*/
		NULL,/*���ڹ����ļ��ı��ʽ: *.txt*/
		TRUE/*�Ƿ����¿�ʼɨ��*/
	);
	if (!NT_SUCCESS(isb.Status)) {
		return isb.Status;
	}
	// �����ļ����
	*phDir = hDir;
	return STATUS_SUCCESS;
}
NTSTATUS FindNextFile(HANDLE hDir, FILE_BOTH_DIR_INFORMATION* pFileInfo, int nInfoSize)
{
	IO_STATUS_BLOCK isb = { 0 };
	ZwQueryDirectoryFile(
		hDir,
		NULL,/*�����첽IO*/
		NULL,
		NULL,
		&isb,
		pFileInfo,/*�����ļ���Ϣ�Ļ�����*/
		nInfoSize,/*���������ֽ���.*/
		FileBothDirectoryInformation,/*Ҫ��ȡ����Ϣ������*/
		TRUE,/*�Ƿ�ֻ����һ���ļ���Ϣ*/
		NULL,/*���ڹ����ļ��ı��ʽ: *.txt*/
		FALSE/*�Ƿ����¿�ʼɨ��*/
	);
	return isb.Status;
}
LONG GetFunticonAddr(PKSYSTEM_SERVICE_TABLE KeServiceDescriptorTable, LONG lgSsdtIndex)
{
	LONG lgSsdtAddr = 0;	//��ȡSSDT��Ļ�ַ	
	lgSsdtAddr = (LONG)KeServiceDescriptorTable->ServiceTableBase;
	PLONG plgSsdtFunAddr = 0; 	//��ȡ�ں˺����ĵ�ַָ��	
	plgSsdtFunAddr = (PLONG)(lgSsdtAddr + lgSsdtIndex * 4); 	//�����ں˺����ĵ�ַ	
	return (*plgSsdtFunAddr);
}

// �Զ�����������ǲ����
NTSTATUS OnEnumDriver1(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 1 ��ȡ˫�������׵�ַ
	PDRIVER_OBJECT pDriver = pDevice->DriverObject;// �豸�����������������
	PLDR_DATA_TABLE_ENTRY pLdr = pDriver->DriverSection;// ����������Ϣ���ɵ�˫������
	PLDR_DATA_TABLE_ENTRY pBegin = pLdr;// �����׵�ַ
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;
	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif
	// 3 ��ȡ��������
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
	// 4 ���ݴ���-д��3��
	RtlCopyMemory(pBuff, &driverCount, sizeof(driverCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = sizeof(driverCount);// �ܹ������ֽ���
	return status;
}
NTSTATUS OnEnumDriver2(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 1 ��ȡ˫���������ַ
	PDRIVER_OBJECT pDriver = pDevice->DriverObject;
	PLDR_DATA_TABLE_ENTRY pLdr = pDriver->DriverSection;
	PLDR_DATA_TABLE_ENTRY pBegin = pLdr;
	// 2 ��ȡIO������(���߹���
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

	// 3 ������д��3��������
	PDRIVERINFO pDriverInfo = (PDRIVERINFO)pBuff;
	__try
	{
		do
		{
			// д����ֶ�
			//RtlCopyMemory(pDriverInfo->name, pLdr->FullDllName.Buffer, pLdr->FullDllName.Length);// here ����
			_tcscpy_s(pDriverInfo->name, sizeof(pDriverInfo->name), pLdr->FullDllName.Buffer);
			pDriverInfo->base = pLdr->DllBase;
			pDriverInfo->size = pLdr->SizeOfImage;

			pDriverInfo++;// ָ�����
			pLdr = (PLDR_DATA_TABLE_ENTRY)pLdr->InLoadOrderLinks.Flink;
		} while (pBegin != pLdr);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("Exception: 0x%08X\n", GetExceptionCode()));
	}
	// 4 �������״̬������������
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = (ULONG)pDriverInfo - (ULONG)pBuff;// β��ַ-�׵�ַ=�����С
	return status;
}
NTSTATUS OnEnumProcess1(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 ��ȡ������
	ULONG ProcessCount = 0;
	PEPROCESS proc = NULL;
	// �趨PID��Χ,ѭ������
	for (int i = 4; i < 100000; i += 4)
	{
		// ��ͨ��PID���ҵ�EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &proc)))
		{
			// ��һ���жϽ����Ƿ���Ч
			ULONG TableCode = *(ULONG*)((ULONG)proc + 0xF4);
			if (TableCode)
			{
				ProcessCount++;// ����+1 
				KdPrint(("%d : %s\n", ProcessCount, PsGetProcessImageFileName(proc)));
				ObDereferenceObject(proc);// �ݼ����ü���
			}

		}
	}
	// 4 ���ݴ���-д��3��
	RtlCopyMemory(pBuff, &ProcessCount, sizeof(ProcessCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = sizeof(ProcessCount);// �ܹ������ֽ���
	return status;
}
NTSTATUS OnEnumProcess2(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 ��ȡ������
	//ULONG ProcessCount = 0;
	PEPROCESS proc = NULL;
	PPROCESSINFO pProcessInfo = (PPROCESSINFO)pBuff;
	// �趨PID��Χ,ѭ������
	for (int i = 4; i < 100000; i += 4)
	{
		// ��ͨ��PID���ҵ�EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &proc)))
		{
			ULONG TableCode = *(ULONG*)((ULONG)proc + 0xF4);
			if (TableCode)
			{
				// char ������wchar,3������listǰ,��%��S����ʽ��,Сs����
				_tcscpy_s(pProcessInfo->name, sizeof(pProcessInfo->name), PsGetProcessImageFileName(proc));
				pProcessInfo->PID = PsGetProcessId(proc);

				pProcessInfo++;// ָ�����
				ObDereferenceObject(proc);// �ݼ����ü���
			}
		}
	}
	// 4 ���ݴ���-д��3��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = (ULONG)pProcessInfo - (ULONG)pBuff;// �ܹ������ֽ���
	return status;
}
NTSTATUS OnEnumModule1(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 ��ȡ��ǰ����ģ����
	//KdBreakPoint();
	ULONG ModuleCount = 0;
	ULONG ProcessCount = 0;
	PEPROCESS proc = NULL;
	int ProcIndex = *(int*)pBuff;// ��ǰ����
	// �趨PID��Χ,ѭ������
	for (int i = 4; i < 100000; i += 4)
	{
		// ��ͨ��PID���ҵ�EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &proc)))
		{
			ULONG TableCode = *(ULONG*)((ULONG)proc + 0xF4);
			if (TableCode)
			{


				// �ҵ����Ӧ�Ľ���
				if (ProcIndex == ProcessCount)
				{
					// ����ģ��
					// 1. �ҵ�PEB(����PEB���û���ռ�,�����Ҫ���̹ҿ�
					KAPC_STATE kapc_status = { 0 };
					KeStackAttachProcess(proc, &kapc_status);
					// 2. �ҵ�PEB.Ldr(ģ������)
					struct _PEB* peb = PsGetProcessPeb(proc);
					if (peb != NULL)
					{
						__try {
							// 3. ����ģ������
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
								// �ҵ���һ��
								pLdrEntry = (LDR_DATA_TABLE_ENTRY*)pLdrEntry->InLoadOrderLinks.Flink;
							} while (pBegin != pLdrEntry);
						}
						__except (EXCEPTION_EXECUTE_HANDLER) {}
					}


					KeUnstackDetachProcess(&kapc_status);// ����ҿ�
					ObDereferenceObject(proc);// �ݼ����ü���
				}
				ProcessCount++;// ���̸���+1 	
			}
		}
	}

	// 4 ���ݴ���-д��3��
	RtlCopyMemory(pBuff, &ModuleCount, sizeof(ModuleCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = sizeof(ModuleCount);// �ܹ������ֽ���
	return status;
}
NTSTATUS OnEnumModule2(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 ��ȡ��ǰ����ģ����
	//KdBreakPoint();
	ULONG ModuleCount = 0;
	ULONG ProcessCount = 0;
	PEPROCESS proc = NULL;
	int ProcIndex = *(int*)pBuff;// ��ǰ����,�Ƚ���������������
	PMODULEINFO pModuleInfo = NULL;
	// �趨PID��Χ,ѭ������
	for (int i = 4; i < 100000; i += 4)
	{
		// ��ͨ��PID���ҵ�EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &proc)))
		{
			ULONG TableCode = *(ULONG*)((ULONG)proc + 0xF4);
			if (TableCode)
			{
				// �ҵ����Ӧ�Ľ���
				if (ProcIndex == ProcessCount)
				{
					// ����ģ��
					// 1. �ҵ�PEB(����PEB���û���ռ�,�����Ҫ���̹ҿ�
					KAPC_STATE kapc_status = { 0 };
					KeStackAttachProcess(proc, &kapc_status);
					// 2. �ҵ�PEB.Ldr(ģ������)
					struct _PEB* peb = PsGetProcessPeb(proc);
					if (peb != NULL)
					{
						pModuleInfo = (PMODULEINFO)pBuff;// �ٽ��������������
						__try {
							// 3. ����ģ������
							LDR_DATA_TABLE_ENTRY* pLdrEntry = (LDR_DATA_TABLE_ENTRY*)peb->Ldr->InLoadOrderModuleList.Flink;
							LDR_DATA_TABLE_ENTRY* pBegin = pLdrEntry;
							do
							{
								KdPrint(("\t%d BASE:%p SIZE:%06X %wZ\n",
									ModuleCount,
									pLdrEntry->DllBase,
									pLdrEntry->SizeOfImage,
									&pLdrEntry->FullDllName));

								// д����ֶ�
								_tcscpy_s(pModuleInfo->name, sizeof(pModuleInfo->name), pLdrEntry->FullDllName.Buffer);
								pModuleInfo->base = pLdrEntry->DllBase;
								pModuleInfo->size = pLdrEntry->SizeOfImage;

								pModuleInfo++;// ָ�����

								ModuleCount++;
								// �ҵ���һ��
								pLdrEntry = (LDR_DATA_TABLE_ENTRY*)pLdrEntry->InLoadOrderLinks.Flink;
							} while (pBegin != pLdrEntry);
						}
						__except (EXCEPTION_EXECUTE_HANDLER) {}
					}


					KeUnstackDetachProcess(&kapc_status);// ����ҿ�
					ObDereferenceObject(proc);// �ݼ����ü���
				}
				ProcessCount++;// ���̸���+1 	
			}
		}
	}

	// 4 ���ݴ���-д��3��
	//RtlCopyMemory(pBuff, &ModuleCount, sizeof(ModuleCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = (ULONG)pModuleInfo - (ULONG)pBuff;// β��ַ-�׵�ַ=�����С
	return status;
}
NTSTATUS OnEnumThread1(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 ��ȡ��ǰ����ģ����
	//KdBreakPoint();
	ULONG ThreadCount = 0;
	ULONG ProcessCount = 0;
	PEPROCESS pEProcess = NULL;
	PETHREAD pEThread = NULL;
	int ProcIndex = *(int*)pBuff;// ��ǰ����
	// �趨PID��Χ,ѭ������
	for (int i = 4; i < 100000; i += 4)
	{
		// ��ͨ��PID���ҵ�EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &pEProcess)))
		{
			ULONG TableCode = *(ULONG*)((ULONG)pEProcess + 0xF4);
			if (TableCode)
			{
				// �ҵ����Ӧ�Ľ���
				if (ProcIndex == ProcessCount)
				{
					//KdBreakPoint();
					KdPrint(("\tPID:%d %s\n", (ULONG)PsGetProcessId(pEProcess), PsGetProcessImageFileName(pEProcess)));

					// �����߳�
					for (ULONG j = 4; j < 0x25600; j += 4)
					{
						// ��ͨ��TID���ҵ�ETHREAD
						if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)j, &pEThread)))
						{
							// ��ȡ�߳���������,�������
							PEPROCESS proc = IoThreadToProcess(pEThread);
							if (pEProcess == proc)
							{
								KdPrint(("\t%d TID:%d\n", ThreadCount, (ULONG)PsGetThreadId(pEThread)));
								ThreadCount++;
							}
							ObDereferenceObject(pEThread);// �ݼ����ü���
						}
					}

					ObDereferenceObject(pEProcess);// �ݼ����ü���
				}
				ProcessCount++;// ���̸���+1 
			}
		}
	}
	// 4 ���ݴ���-д��3��
	RtlCopyMemory(pBuff, &ThreadCount, sizeof(ThreadCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = sizeof(ThreadCount);// �ܹ������ֽ���
	return status;
}
NTSTATUS OnEnumThread2(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 ��ȡ��ǰ����ģ����
	//KdBreakPoint();
	ULONG ThreadCount = 0;
	ULONG ProcessCount = 0;
	PEPROCESS pEProcess = NULL;
	PETHREAD pEThread = NULL;
	int ProcIndex = *(int*)pBuff;// ��ǰ����
	PTHREADINFO pThreadInfo = NULL;
	// �趨PID��Χ,ѭ������
	for (int i = 4; i < 1000; i += 4)
	{
		// ��ͨ��PID���ҵ�EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &pEProcess)))
		{
			ULONG TableCode = *(ULONG*)((ULONG)pEProcess + 0xF4);
			if (TableCode)
			{
				// �ҵ����Ӧ�Ľ���
				if (ProcIndex == ProcessCount)
				{
					pThreadInfo = (PTHREADINFO)pBuff;// �ٽ��������������
					//KdBreakPoint();
					KdPrint(("\tPID:%d %s\n", (ULONG)PsGetProcessId(pEProcess), PsGetProcessImageFileName(pEProcess)));

					// �����߳�
					for (ULONG j = 4; j < 1000; j += 4)
					{
						// ��ͨ��TID���ҵ�ETHREAD
						if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)j, &pEThread)))
						{
							// ��ȡ�߳���������,�������
							PEPROCESS proc = IoThreadToProcess(pEThread);
							if (pEProcess == proc)
							{

								// д����ֶ�
								pThreadInfo->TID = PsGetThreadId(pEThread);
								//pThreadInfo->OwnerPID = PsGetProcessId(pEProcess);
								pThreadInfo++;// ָ�����

								KdPrint(("\t%d TID:%d\n", ThreadCount, (ULONG)PsGetThreadId(pEThread)));
								ThreadCount++;
							}
							ObDereferenceObject(pEThread);// �ݼ����ü���
						}
					}

					ObDereferenceObject(pEProcess);// �ݼ����ü���
				}
				ProcessCount++;// ���̸���+1 
			}
		}
	}
	// 4 ���ݴ���-д��3��
	//RtlCopyMemory(pBuff, &ThreadCount, sizeof(ThreadCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = (ULONG)pThreadInfo - (ULONG)pBuff;// �ܹ������ֽ���
	return status;
}
NTSTATUS OnEnumIDT1(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// ����IDT
	//KdBreakPoint();
	IDT_INFO SIDT = { 0,0,0 };
	PIDT_ENTRY pIDTEntry = NULL;
	ULONG uAddr = 0;
	// ��ȡIDT���ַ
	_asm sidt SIDT;
	// ��ȡIDT�������ַ
	pIDTEntry = (PIDT_ENTRY)MAKELONG(SIDT.uLowIdtBase, SIDT.uHighIdtBase);
	// ��ȡIDT��Ϣ
	//ULONG IDTEntryCount = 0;
	PIDTINFO pIDTInfo = (PIDTINFO)pBuff;
	KdPrint(("---------------�ж���������---------\n"));
	for (ULONG i = 0; i < 0x100; i++)
	{
		ULONG Idt_address = MAKELONG(pIDTEntry[i].uOffsetLow, pIDTEntry[i].uOffsetHigh);
		KdPrint(("addr: %08X, int: %d, selector: %d, GateType:%d, DPL: %d\n",
			Idt_address,// �жϵ�ַ
			i,// �жϺ�
			pIDTEntry[i].uSelector,// ��ѡ����
			pIDTEntry[i].GateType,//����
			pIDTEntry[i].DPL//��Ȩ�ȼ�
			));
		pIDTInfo->addr = Idt_address;
		pIDTInfo->uSelector = pIDTEntry[i].uSelector;
		pIDTInfo->GateType = pIDTEntry[i].GateType;
		pIDTInfo->DPL = pIDTEntry[i].DPL;

		pIDTInfo++;// ָ�����

		//IDTEntryCount++;
	}

	// 4 ���ݴ���-д��3��
	//RtlCopyMemory(pBuff, &IDTEntryCount, sizeof(IDTEntryCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = (ULONG)pIDTInfo - (ULONG)pBuff;// �ܹ������ֽ���
	return status;
}
NTSTATUS OnEnumGDT1(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// ����GDT
	//KdBreakPoint();
	GDT_INFO SGDT = { 0,0,0 };
	PGDT_ENTRY pGDTEntry = NULL;
	ULONG uAddr = 0;
	// ��ȡGDT���ַ
	_asm sgdt SGDT;
	// ��ȡGDT�������ַ
	pGDTEntry = (PGDT_ENTRY)MAKELONG(SGDT.uLowGdtBase, SGDT.uHighGdtBase);
	// ��ȡGDT��Ϣ
	//ULONG GDTEntryCount = 0;
	PGDTINFO pGDTInfo = (PGDTINFO)pBuff;
	KdPrint(("---------------�ж���������---------\n"));
	for (ULONG i = 0; i < 0x100; i++)
	{
		ULONG Gdt_address = 0;
		Gdt_address = MAKELONG(pGDTEntry[i].Base16_31, pGDTEntry[i].Base0_7);
		Gdt_address = MAKELONG(Gdt_address, pGDTEntry[i].Base24_31);
		ULONG Gdt_limit = MAKELONG(pGDTEntry[i].Limit_0_15, pGDTEntry[i].Limit_16_19);
		// ��ӡ
		KdPrint(("addr: %08X, limit: %d, P: %d, G:%d, S:%d,Type:%d,D/B:%d,DPL:%d\n",
			Gdt_address, Gdt_limit,
			pGDTEntry[i].P,
			pGDTEntry[i].G,
			pGDTEntry[i].S,
			pGDTEntry[i].Type,
			pGDTEntry[i].D_B,
			pGDTEntry[i].DPL
			));
		// ����
		pGDTInfo->Base = Gdt_address;
		pGDTInfo->Limit = Gdt_limit;
		pGDTInfo->P = pGDTEntry[i].P;
		pGDTInfo->G = pGDTEntry[i].G;
		pGDTInfo->S = pGDTEntry[i].S;
		pGDTInfo->Type = pGDTEntry[i].Type;
		pGDTInfo->D_B = pGDTEntry[i].D_B;
		pGDTInfo->DPL = pGDTEntry[i].DPL;

		pGDTInfo++;// ָ�����

		//GDTEntryCount++;
	}

	// 4 ���ݴ���-д��3��
	//RtlCopyMemory(pBuff, &GDTEntryCount, sizeof(GDTEntryCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = (ULONG)pGDTInfo - (ULONG)pBuff;// �ܹ������ֽ���
	return status;
}
NTSTATUS OnHideDriver(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 1 ��ȡ˫�������׵�ַ
	PDRIVER_OBJECT pDriver = pDevice->DriverObject;// �豸�����������������
	PLDR_DATA_TABLE_ENTRY pLdr = pDriver->DriverSection;// ����������Ϣ���ɵ�˫������
	PLDR_DATA_TABLE_ENTRY pBegin = pLdr;// �����׵�ַ
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;
	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif
	// 3 ��ȡ��������
	KdBreakPoint();
	ULONG driverCount = 0;
	int driverIndex = *(int*)pBuff;// ��ǰ����
	__try
	{
		do
		{
			// �ҵ�Ŀ������
			if (driverIndex == driverCount)
			{
				KdPrint(("%d %08X | %06X | %wZ\n", driverCount, pLdr->DllBase, pLdr->SizeOfImage, &pLdr->FullDllName));

				// �޸�Flink��Blinkָ��,������Ҫ���ص�����
				// (ǰ Ŀ�� ��)����,ǰָ��,��ָǰ,�����м��Ŀ��
				*((ULONG*)pLdr->InLoadOrderLinks.Blink) = (ULONG)pLdr->InLoadOrderLinks.Flink;
				pLdr->InLoadOrderLinks.Flink->Blink = pLdr->InLoadOrderLinks.Blink;
				// �����������Ե�BSoD(����
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
	// 4 ���ݴ���-д��3��
	//RtlCopyMemory(pBuff, &driverCount, sizeof(driverCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = 0;// �ܹ������ֽ���
	return status;
}
NTSTATUS OnHideProcess(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 ��ȡ������
	//KdBreakPoint();
	int processIndex = *(int*)pBuff;// Ŀ�����
	ULONG ProcessCount = 0;
	PEPROCESS proc = NULL;
	// �趨PID��Χ,ѭ������
	for (int i = 4; i < 100000; i += 4)
	{
		// ��ͨ��PID���ҵ�EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &proc)))
		{
			ULONG TableCode = *(ULONG*)((ULONG)proc + 0xF4);
			if (TableCode)
			{


				// �ҵ�Ҫ���ص�Ŀ�����
				if (processIndex == ProcessCount)
				{
					KdPrint(("%d : %s\n", ProcessCount, PsGetProcessImageFileName(proc)));

					// ��ȡ���̶����ڵĵ�ǰ���������
					LIST_ENTRY* pProcList = (LIST_ENTRY*)((ULONG)proc + 0xB8);

					// �޸�Flink��Blinkָ��,������Ҫ���ص�����(ǰ Ŀ�� ��)
					*((ULONG*)pProcList->Blink) = (ULONG)pProcList->Flink;//��ָǰ
					pProcList->Flink->Blink = pProcList->Blink;//ǰָ��
					// �����������Ե�BSoD(����
					pProcList->Flink = (LIST_ENTRY*)&(pProcList->Flink);
					pProcList->Blink = (LIST_ENTRY*)&(pProcList->Flink);

					break;

				}
				ProcessCount++;// ����+1 

				ObDereferenceObject(proc);// �ݼ����ü���
			}

		}
	}
	// 4 ���ݴ���-д��3��
	//RtlCopyMemory(pBuff, &ProcessCount, sizeof(ProcessCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = 0;// �ܹ������ֽ���
	return status;
}
NTSTATUS OnKillProcess(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;

	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 ��ȡ������
	//KdBreakPoint();
	int processIndex = *(int*)pBuff;// Ŀ�����
	ULONG ProcessCount = 0;
	PEPROCESS proc = NULL;
	// �趨PID��Χ,ѭ������
	for (int i = 4; i < 100000; i += 4)
	{
		// ��ͨ��PID���ҵ�EPROCESS
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &proc)))
		{
			ULONG TableCode = *(ULONG*)((ULONG)proc + 0xF4);
			if (TableCode)
			{
				// �ҵ�Ҫ������Ŀ�����
				if (processIndex == ProcessCount)
				{
					KdPrint(("%d : %s\n", ProcessCount, PsGetProcessImageFileName(proc)));

					// ��������
					HANDLE hProcess = NULL;
					OBJECT_ATTRIBUTES objAttribute = { sizeof(OBJECT_ATTRIBUTES) };
					CLIENT_ID clientID = { 0 };
					clientID.UniqueProcess = (HANDLE)PsGetProcessId(proc);
					clientID.UniqueThread = 0;
					ZwOpenProcess(&hProcess, 1, &objAttribute, &clientID);//��ȡ���̾��
					if (hProcess)
					{
						ZwTerminateProcess(hProcess, 0);
						ZwClose(hProcess);
					}

					break;

				}
				ProcessCount++;// ����+1 

				ObDereferenceObject(proc);// �ݼ����ü���
			}


		}
	}
	// 4 ���ݴ���-д��3��
	//RtlCopyMemory(pBuff, &ProcessCount, sizeof(ProcessCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = 0;// �ܹ������ֽ���
	return status;
}
NTSTATUS OnEnumFile1(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 1 ��ȡ˫�������׵�ַ
	PDRIVER_OBJECT pDriver = pDevice->DriverObject;// �豸�����������������
	PLDR_DATA_TABLE_ENTRY pLdr = pDriver->DriverSection;// ����������Ϣ���ɵ�˫������
	PLDR_DATA_TABLE_ENTRY pBegin = pLdr;// �����׵�ַ
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;
	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// �����ļ�
	//KdBreakPoint();
	ULONG fileCount = 0;
	HANDLE hDir = NULL;
	char buff[sizeof(FILE_BOTH_DIR_INFORMATION) + 266 * 2];
	FILE_BOTH_DIR_INFORMATION* pFileInfo = (FILE_BOTH_DIR_INFORMATION*)buff;
	status = FindFirstFile(_TEXT("\\??\\C:\\"), &hDir, pFileInfo, sizeof(buff));
	if (!NT_SUCCESS(status))
	{
		KdPrint(("���ҵ�һ���ļ�ʧ��:%08X\n", status));
		return status;
	}
	do
	{
		// ����Filename�ֶ�,��ֹ����
		UNICODE_STRING uniName;
		TCHAR name[1024] = { 0 };
		RtlZeroMemory(name, 1024);
		RtlCopyMemory(name, pFileInfo->FileName, pFileInfo->FileNameLength);// �������
		RtlInitUnicodeString(&uniName, name);
		// ��ӡ��Ϣ
		KdPrint(("index:%d,�ļ���:%wZ,ռ�ÿռ�:%lld,����ֵ:%d,����ʱ��:%u, �޸�ʱ��:%llu\n", fileCount, &uniName, pFileInfo->AllocationSize.QuadPart, pFileInfo->FileAttributes, pFileInfo->CreationTime, pFileInfo->ChangeTime.QuadPart));
		// ����+1
		fileCount++;
	} while (STATUS_SUCCESS == FindNextFile(hDir, pFileInfo, sizeof(buff)));


	// 4 ���ݴ���-д��3��
	RtlCopyMemory(pBuff, &fileCount, sizeof(fileCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = sizeof(fileCount);// �ܹ������ֽ���
	return status;
}
NTSTATUS OnEnumFile2(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 1 ��ȡ˫�������׵�ַ
	PDRIVER_OBJECT pDriver = pDevice->DriverObject;// �豸�����������������
	PLDR_DATA_TABLE_ENTRY pLdr = pDriver->DriverSection;// ����������Ϣ���ɵ�˫������
	PLDR_DATA_TABLE_ENTRY pBegin = pLdr;// �����׵�ַ
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;
	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// �����ļ�
	//KdBreakPoint();
	PFILEINFO pFileInformation = (PFILEINFO)pBuff;
	ULONG fileCount = 0;
	HANDLE hDir = NULL;
	char buff[sizeof(FILE_BOTH_DIR_INFORMATION) + 266 * 2];
	FILE_BOTH_DIR_INFORMATION* pFileInfo = (FILE_BOTH_DIR_INFORMATION*)buff;
	status = FindFirstFile(_TEXT("\\??\\C:\\"), &hDir, pFileInfo, sizeof(buff));
	if (!NT_SUCCESS(status))
	{
		KdPrint(("���ҵ�һ���ļ�ʧ��:%08X\n", status));
		return status;
	}
	do
	{
		// ����Filename�ֶ�,��ֹ����
		UNICODE_STRING uniName;
		TCHAR name[1024] = { 0 };
		RtlZeroMemory(name, 1024);
		RtlCopyMemory(name, pFileInfo->FileName, pFileInfo->FileNameLength);// �������
		RtlInitUnicodeString(&uniName, name);

		KdPrint(("index:%d,�ļ���:%wZ,ռ�ÿռ�:%lld,����ֵ:%d,����ʱ��:%llu, �޸�ʱ��:%llu\n", fileCount, &uniName, pFileInfo->AllocationSize.QuadPart, pFileInfo->FileAttributes, pFileInfo->CreationTime.QuadPart, pFileInfo->ChangeTime.QuadPart));
		fileCount++;

		_tcscpy_s(pFileInformation->fileName, sizeof(pFileInformation->fileName), uniName.Buffer);
		pFileInformation->attribute = pFileInfo->FileAttributes;
		pFileInformation->size = pFileInfo->AllocationSize.QuadPart;
		pFileInformation->createTime = pFileInfo->CreationTime.QuadPart;
		pFileInformation->changeTime = pFileInfo->ChangeTime.QuadPart;

		pFileInformation++;// ָ�����


	} while (STATUS_SUCCESS == FindNextFile(hDir, pFileInfo, sizeof(buff)));


	// 4 ���ݴ���-д��3��
	//RtlCopyMemory(pBuff, &fileCount, sizeof(fileCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = (ULONG)pFileInformation - (ULONG)pBuff;// �ܹ������ֽ���
	return status;
}
NTSTATUS OnDeleteFile(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 1 ��ȡ˫�������׵�ַ
	PDRIVER_OBJECT pDriver = pDevice->DriverObject;// �豸�����������������
	PLDR_DATA_TABLE_ENTRY pLdr = pDriver->DriverSection;// ����������Ϣ���ɵ�˫������
	PLDR_DATA_TABLE_ENTRY pBegin = pLdr;// �����׵�ַ
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;
	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// �����ļ�
	KdBreakPoint();
	int fileIndex = *(int*)pBuff;// ��ɾ���ļ�����
	ULONG fileCount = 0;
	HANDLE hDir = NULL;
	char buff[sizeof(FILE_BOTH_DIR_INFORMATION) + 266 * 2];
	FILE_BOTH_DIR_INFORMATION* pFileInfo = (FILE_BOTH_DIR_INFORMATION*)buff;
	status = FindFirstFile(_TEXT("\\??\\C:\\"), &hDir, pFileInfo, sizeof(buff));
	if (!NT_SUCCESS(status))
	{
		KdPrint(("���ҵ�һ���ļ�ʧ��:%08X\n", status));
		return status;
	}
	do
	{

		// �ҵ�Ŀ������
		if (fileIndex == fileCount)
		{
			// ����Filename�ֶ�,��ֹ����
			const UNICODE_STRING uniName;
			TCHAR name[1024] = { 0 };
			RtlZeroMemory(name, 1024);
			RtlCopyMemory(name, pFileInfo->FileName, pFileInfo->FileNameLength);// �������
			RtlInitUnicodeString(&uniName, name);
			//RtlInitEmptyUnicodeString(&uniName, name,1024);
			// ��ӡ��Ϣ
			KdPrint(("index:%d,�ļ���:%wZ\n", fileCount, &uniName));


			// ��ʼɾ���ļ�
			UNICODE_STRING path;
			//RtlInitEmptyUnicodeString(&path, _TEXT("\\??\\C:\\"), 2048);
			RtlInitUnicodeString(&path, _TEXT("\\??\\C:\\�½��ı��ĵ�.txt"));
			//RtlInitUnicodeString(&path, _TEXT("\\??\\C:\\"));
			//RtlAppendUnicodeStringToString(&path, &uniName);
			KdPrint(("%wZ\n",&path));
			// 1. ��ʼ��OBJECT_ATTRIBUTES������
			OBJECT_ATTRIBUTES objAttrib = { 0 };
			ULONG  ulAttributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
			InitializeObjectAttributes(&objAttrib,&path,ulAttributes,NULL,NULL);
			// 2. ɾ��ָ���ļ�/�ļ���
			ZwDeleteFile(&objAttrib);


			break;
		}
		// ����+1
		fileCount++;
	} while (STATUS_SUCCESS == FindNextFile(hDir, pFileInfo, sizeof(buff)));


	// 4 ���ݴ���-д��3��
	//RtlCopyMemory(pBuff, &fileCount, sizeof(fileCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = 0;// �ܹ������ֽ���
	return status;
}
NTSTATUS OnEnumSSDT1(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬

	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;
	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 ��ȡ��������
	//KdBreakPoint();
	ULONG SSDTCount = 0;

	// ��ȡϵͳ������������
	PETHREAD* pCurThread = PsGetCurrentThread();
	KSERVICE_TABLE_DESCRIPTOR * pServiceTable = (KSERVICE_TABLE_DESCRIPTOR*)
		(*(ULONG*)((ULONG_PTR)pCurThread + 0xBC));
	SSDTCount = pServiceTable->ntoskrnl.NumberOfService;// SSDT�к�������
	// 4 ���ݴ���-д��3��
	RtlCopyMemory(pBuff, &SSDTCount, sizeof(SSDTCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = sizeof(SSDTCount);// �ܹ������ֽ���
	return status;
}
NTSTATUS OnEnumSSDT2(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;
	// ������״̬���¶�
#ifdef _DEBUG
	KdBreakPoint();
#endif

	// 3 ��ȡ��������
	ULONG SSDTCount = 0;
	PSSDTINFO pSSDTInfo = (PSSDTINFO)pBuff;
	// ��ȡϵͳ������������
	PETHREAD* pCurThread = PsGetCurrentThread();
	KSERVICE_TABLE_DESCRIPTOR * pServiceTable = (KSERVICE_TABLE_DESCRIPTOR*)
		(*(ULONG*)((ULONG_PTR)pCurThread + 0xBC));
	SSDTCount = pServiceTable->ntoskrnl.NumberOfService;// SSDT�к�������
	for (int i = 0; i < SSDTCount; i++)
	{
		pSSDTInfo->funcAddr = GetFunticonAddr(&pServiceTable->ntoskrnl, i);

		pSSDTInfo++;
	}

	// 4 ���ݴ���-д��3��
	//RtlCopyMemory(pBuff, &SSDTCount, sizeof(SSDTCount));//�ڴ濽��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = (ULONG)pSSDTInfo-(ULONG)pBuff;// �ܹ������ֽ���
	return status;
}
NTSTATUS OnHookSysEnter(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;// ����״̬
	// 2 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;
	// 3 ��װhook
	KdBreakPoint();
	g_uPid = *(int*)pBuff;//��ȡPID
	installSysenterHook();
	KdPrint(("%d\n", g_uPid));
	// 4 ���ݴ���-д��3��
	pIrp->IoStatus.Status = status;// ���״̬
	pIrp->IoStatus.Information = 0;// �ܹ������ֽ���
	return status;
}

// �󶨿���������ǲ����
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

// ȫ�ֱ���
LDR_DATA_TABLE_ENTRY* pLdr = NULL;
LDR_DATA_TABLE_ENTRY* pBegin = NULL;
int driverCount = 0;

// ж�غ���
void OnUnload(DRIVER_OBJECT* object)
{
	KdPrint(("������ж��\n"));
	// ж���豸
	IoDeleteDevice(object->DeviceObject);
	// ɾ����������
	UNICODE_STRING symName = RTL_CONSTANT_STRING(NAME_SYMBOL);
	IoDeleteSymbolicLink(&symName);
	// ж��HOOK
	uninstallSysenterHook();
}
// ��ǲ����
NTSTATUS OnCreate(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	pDevice;
	KdPrint(("�豸������\n"));
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS OnClose(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	pDevice;
	KdPrint(("�豸���ر�\n"));
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS OnDeviceIoControl(DEVICE_OBJECT *pDevice, IRP *pIrp)
{
	pDevice;
	//DbgBreakPoint();
	// 1 ��ȡIO������(���߹���
	TCHAR* pBuff = NULL;
	if (pIrp->MdlAddress != NULL)
		pBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	else if (pIrp->AssociatedIrp.SystemBuffer != NULL)
		pBuff = pIrp->AssociatedIrp.SystemBuffer;
	else if (pIrp->UserBuffer != NULL)
		pBuff = pIrp->UserBuffer;
	else
		pBuff = NULL;
	// 2 ��ȡIOջ�������Ϣ
	IO_STACK_LOCATION* pIoStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG uInputLen = pIoStack->Parameters.DeviceIoControl.InputBufferLength;//���뻺�����ֽ���
	ULONG uOutputLen = pIoStack->Parameters.DeviceIoControl.OutputBufferLength;//����������ֽ���
	ULONG uCtrlCode = pIoStack->Parameters.DeviceIoControl.IoControlCode;//������
	KdPrint(("������:%08X ���볤��:%d �������:%d\n", uCtrlCode, uInputLen, uOutputLen));

	// 3 ������Ӧ����ǲ����
	for (int i = 0; i < _countof(g_handler); ++i)
	{
		if (g_handler[i].ctrl_code == uCtrlCode)
		{
			g_handler[i].callback(pDevice, pIrp);
		}
	}


	//// 4 ���ݿ������������Ӧ����
	//switch (uCtrlCode)
	//{
	//case readProcessMemory:
	//{
	//	// ��ȡ3����Ϣ
	//	ULONG* pPid = (ULONG*)pBuff;
	//	// ��0������
	//	KdPrint(("[�ں˲�]��ȡ�����ڴ������\n"));
	//	KdPrint(("pid=%d\n", *pPid));
	//	// �����3��
	//	RtlCopyMemory(pBuff, _TEXT("aaaaaaaaa"), 20);// �������
	//	pIrp->IoStatus.Information = 20;// ������ֽ���
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
	//	// ��ȡ3����Ϣ
	//	struct _ProcessInfo* pProcInfo = (struct _ProcessInfo*)pBuff;
	//	// ��0������
	//	KdPrint(("[�ں˲�]д�����ڴ������\n"));
	//	KdPrint(("pid=%d address=%p buffsize=%d\n",
	//		pProcInfo->dwPid,
	//		pProcInfo->address,
	//		pProcInfo->buffSize));
	//	// �����3��
	//	RtlCopyMemory(pBuff, _TEXT("bbbbbbbbbbb"), 20);
	//	pIrp->IoStatus.Information = 20;
	//	break;
	//}
	//case listDriver:
	//{
	//	int count = 1;
	//	DRIVERINFO driverInfo = { 0 };
	//	KdPrint(("���ػ�ַ | ��  С | ·��\n"));
	//	__try 
	//	{
	//		do
	//		{
	//			KdPrint(("%d %08X | %06X | %wZ\n",count,pLdr->DllBase,pLdr->SizeOfImage,&pLdr->FullDllName));
	//			////���ν���Ϣ��ֵ��������
	//			//RtlCopyMemory(driverInfo.name, pLdr->FullDllName.Buffer, pLdr->FullDllName.Length);
	//			//driverInfo.size = pLdr->SizeOfImage;
	//			//driverInfo.base = pLdr->DllBase;
	//			////���û�������������
	//			//RtlCopyMemory(pBuff, (PVOID)&driverInfo, sizeof(driverInfo));
	//			//pBuff = pBuff + sizeof(driverInfo);
	//			
	//			count++;
	//			pLdr = (LDR_DATA_TABLE_ENTRY*)(pLdr->InLoadOrderLinks.Flink);
	//		} while (pBegin != pLdr);
	//	}
	//	__except (EXCEPTION_EXECUTE_HANDLER) 
	//	{
	//		KdPrint(("�����쳣:%08x", GetExceptionCode()));
	//	}
	//	//RtlCopyMemory(pBuff, _TEXT("123123"), 20);// �������
	//	driverCount = count - 1;
	//	pIrp->IoStatus.Information = driverCount;// ������ֽ���
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
	//				//���ν���Ϣ��ֵ��������
	//				RtlCopyMemory(driverInfo.name, pLdr->FullDllName.Buffer, pLdr->FullDllName.Length);
	//				driverInfo.size = pLdr->SizeOfImage;
	//				driverInfo.base = pLdr->DllBase;
	//				//���û�������������
	//				RtlCopyMemory(pBuff, &driverInfo, sizeof(DRIVERINFO));
	//				break;
	//			}
	//			count++;
	//			pLdr = (LDR_DATA_TABLE_ENTRY*)(pLdr->InLoadOrderLinks.Flink);
	//		} while (pBegin != pLdr);
	//	}
	//	__except (EXCEPTION_EXECUTE_HANDLER)
	//	{
	//		KdPrint(("�����쳣:%08x", GetExceptionCode()));
	//	}
	//	pIrp->IoStatus.Information = sizeof(DRIVERINFO);// ������ֽ���
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


	// 5 ����IRP���״̬
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

// ���
NTSTATUS DriverEntry(DRIVER_OBJECT* pDriverObj, UNICODE_STRING* path)
{
	path;
	KdPrint(("����������\n"));
	NTSTATUS status = STATUS_SUCCESS;
	// 1 ��ж�غ���
	pDriverObj->DriverUnload = &OnUnload;
	// 2 �����豸����
	UNICODE_STRING devName = RTL_CONSTANT_STRING(NAME_DEVICE);
	DEVICE_OBJECT* pDevice = NULL;// �������豸�����ָ��.
	status = IoCreateDevice(pDriverObj, 0, &devName, FILE_DEVICE_UNKNOWN, 0, 0, &pDevice);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("�����豸ʧ��,������:%08X\n", status));
		return status;
	}
	pDevice->Flags |= DO_BUFFERED_IO;// ͨѶ��ʽ
	// 3 �󶨷�������
	UNICODE_STRING symbolName = RTL_CONSTANT_STRING(NAME_SYMBOL);
	IoCreateSymbolicLink(&symbolName, &devName);
	// 4 ����ǲ����
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = &OnCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = &OnClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &OnDeviceIoControl;

	// ��װHOOK
	//installSysenterHook();

	return status;
}