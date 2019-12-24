#include <ntddk.h>
#include <stdlib.h>
#include <tchar.h>

// 设备\符号链接名
#define NAME_DEVICE L"\\Device\\deviceARK"
#define NAME_SYMBOL L"\\DosDevices\\deviceARK"

// LDR数据结构体
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
// 驱动信息结构体
typedef struct _DRIVERINFO
{
	PVOID base;
	ULONG size;
	TCHAR name[260];
}DRIVERINFO, *PDRIVERINFO;

// 自定义控制码
#define MYCTLCODE(code) CTL_CODE(FILE_DEVICE_UNKNOWN,0x800+(code),METHOD_BUFFERED,FILE_ANY_ACCESS)
typedef enum _MyCtlCode
{
	enumDriver1 = MYCTLCODE(0),
	enumDriver2 = MYCTLCODE(1),
}MyCtlCode;

// 获取缓冲区
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
	PDRIVERINFO pDriverInfo=(PDRIVERINFO)pBuff;
	__try 
	{
		do 
		{
			// 写入各字段
			//RtlCopyMemory(pDriverInfo->name, pLdr->FullDllName.Buffer, pLdr->FullDllName.Length);// here 乱码
			wcscpy_s(pDriverInfo->name, sizeof(pDriverInfo->name), pLdr->FullDllName.Buffer);
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
	DbgBreakPoint();
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
    status = IoCreateDevice(pDriverObj,0,&devName,FILE_DEVICE_UNKNOWN,0,0,&pDevice);
    if (!NT_SUCCESS(status)) 
	{
        KdPrint(("创建设备失败,错误码:%08X\n", status));
        return status;
    }
    pDevice->Flags |= DO_BUFFERED_IO;// 通讯方式
	// 3 绑定符号链接
    UNICODE_STRING symbolName = RTL_CONSTANT_STRING(NAME_SYMBOL);
    IoCreateSymbolicLink(&symbolName,&devName);
	// 4 绑定派遣函数
    pDriverObj->MajorFunction[IRP_MJ_CREATE] = &OnCreate;
    pDriverObj->MajorFunction[IRP_MJ_CLOSE] = &OnClose;
    pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &OnDeviceIoControl;


	//pLdr = (LDR_DATA_TABLE_ENTRY*)pDriverObj->DriverSection;
	//pBegin = pLdr;

    return status;
}


