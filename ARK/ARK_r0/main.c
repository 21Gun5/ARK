#include <ntddk.h>
#include <stdlib.h>
#include <tchar.h>

// �豸\����������
#define NAME_DEVICE L"\\Device\\deviceARK"
#define NAME_SYMBOL L"\\DosDevices\\deviceARK"

// LDR���ݽṹ��
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
// ������Ϣ�ṹ��
typedef struct _DRIVERINFO
{
	PVOID base;
	ULONG size;
	TCHAR name[260];
}DRIVERINFO, *PDRIVERINFO;

// �Զ��������
#define MYCTLCODE(code) CTL_CODE(FILE_DEVICE_UNKNOWN,0x800+(code),METHOD_BUFFERED,FILE_ANY_ACCESS)
typedef enum _MyCtlCode
{
	enumDriver1 = MYCTLCODE(0),
	enumDriver2 = MYCTLCODE(1),
}MyCtlCode;

// ��ȡ������
void GetUserBuf(IRP* pIrp, void** ppBuf)
{
	IO_STACK_LOCATION* pStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG ulDeviceCtrlCode = pStack->Parameters.DeviceIoControl.IoControlCode;

	if (pIrp->MdlAddress && (METHOD_FROM_CTL_CODE(ulDeviceCtrlCode) & METHOD_OUT_DIRECT))
	{
		*ppBuf = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, 0);
	}
	else if (pIrp->AssociatedIrp.SystemBuffer)
	{
		*ppBuf = pIrp->AssociatedIrp.SystemBuffer;
	}
	else
	{
		*ppBuf = NULL;
		KdPrint(("[**WARNING**]pBuf == NULL\n"));
	}

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
	PDRIVERINFO pDriverInfo=(PDRIVERINFO)pBuff;
	__try 
	{
		do 
		{
			// д����ֶ�
			//RtlCopyMemory(pDriverInfo->name, pLdr->FullDllName.Buffer, pLdr->FullDllName.Length);// here ����
			wcscpy_s(pDriverInfo->name, sizeof(pDriverInfo->name), pLdr->FullDllName.Buffer);
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
	DbgBreakPoint();
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
    status = IoCreateDevice(pDriverObj,0,&devName,FILE_DEVICE_UNKNOWN,0,0,&pDevice);
    if (!NT_SUCCESS(status)) 
	{
        KdPrint(("�����豸ʧ��,������:%08X\n", status));
        return status;
    }
    pDevice->Flags |= DO_BUFFERED_IO;// ͨѶ��ʽ
	// 3 �󶨷�������
    UNICODE_STRING symbolName = RTL_CONSTANT_STRING(NAME_SYMBOL);
    IoCreateSymbolicLink(&symbolName,&devName);
	// 4 ����ǲ����
    pDriverObj->MajorFunction[IRP_MJ_CREATE] = &OnCreate;
    pDriverObj->MajorFunction[IRP_MJ_CLOSE] = &OnClose;
    pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &OnDeviceIoControl;


	//pLdr = (LDR_DATA_TABLE_ENTRY*)pDriverObj->DriverSection;
	//pBegin = pLdr;

    return status;
}


