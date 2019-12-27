#include "KernelFunction.h"
#include <ntifs.h>


void* alloc(ULONG size)
{
	return ExAllocatePool(PagedPool, size);
}

void* reAlloc(void* src, ULONG size)
{
	if (!src)
	{
		return NULL;
	}

	void* data = alloc(size);
	RtlCopyMemory(data, src, size);
	ExFreePool(src);
	return data;
}

//void free(void* data)
//{
//	if (data)
//	{
//		ExFreePool(data);
//	}
//}

NTSTATUS createFile(wchar_t * filepath,
	ULONG access,
	ULONG share,
	ULONG openModel,
	BOOLEAN isDir,
	HANDLE * hFile)
{

	NTSTATUS status = STATUS_SUCCESS;

	IO_STATUS_BLOCK StatusBlock = { 0 };
	ULONG           ulShareAccess = share;
	ULONG ulCreateOpt = FILE_SYNCHRONOUS_IO_NONALERT;

	UNICODE_STRING path;
	RtlInitUnicodeString(&path, filepath);

	// 1. ��ʼ��OBJECT_ATTRIBUTES������
	OBJECT_ATTRIBUTES objAttrib = { 0 };
	ULONG ulAttributes = OBJ_CASE_INSENSITIVE/*�����ִ�Сд*/ | OBJ_KERNEL_HANDLE/*�ں˾��*/;
	InitializeObjectAttributes(&objAttrib,    // ���س�ʼ����ϵĽṹ��
		&path,      // �ļ���������
		ulAttributes,  // ��������
		NULL, NULL);   // һ��ΪNULL

// 2. �����ļ�����
	ulCreateOpt |= isDir ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE;

	status = ZwCreateFile(hFile,                 // �����ļ����
		access,				 // �ļ���������
		&objAttrib,            // OBJECT_ATTRIBUTES
		&StatusBlock,          // ���ܺ����Ĳ������
		0,                     // ��ʼ�ļ���С
		FILE_ATTRIBUTE_NORMAL, // �½��ļ�������
		ulShareAccess,         // �ļ�����ʽ
		openModel,			 // �ļ�������򿪲������򴴽�
		ulCreateOpt,           // �򿪲����ĸ��ӱ�־λ
		NULL,                  // ��չ������
		0);                    // ��չ����������
	return status;
}


NTSTATUS getFileSize(HANDLE hFile, ULONG64* size)
{
	IO_STATUS_BLOCK isb = { 0 };
	FILE_STANDARD_INFORMATION fsi = { 0 };
	NTSTATUS status;
	status = ZwQueryInformationFile(hFile, /*�ļ����*/
		&isb, /*���״̬*/
		&fsi, /*�����ļ���Ϣ�Ļ�����*/
		sizeof(fsi), /*���������ֽ���*/
		FileStandardInformation/*Ҫ��ȡ����Ϣ����*/);
	if (STATUS_SUCCESS == status)
	{
		// �����ļ��ֽ���
		*size = fsi.EndOfFile.QuadPart;
	}
	return status;
}

NTSTATUS readFile(HANDLE hFile,
	ULONG offsetLow,
	ULONG offsetHig,
	ULONG sizeToRead,
	PVOID pBuff,
	ULONG* read)
{
	NTSTATUS status;
	IO_STATUS_BLOCK isb = { 0 };
	LARGE_INTEGER offset;
	// ����Ҫ��ȡ���ļ�ƫ��
	offset.HighPart = offsetHig;
	offset.LowPart = offsetLow;

	status = ZwReadFile(hFile,/*�ļ����*/
		NULL,/*�¼�����,�����첽IO*/
		NULL,/*APC�����֪ͨ����:�����첽IO*/
		NULL,/*���֪ͨ������ĸ��Ӳ���*/
		&isb,/*IO״̬*/
		pBuff,/*�����ļ����ݵĻ�����*/
		sizeToRead,/*Ҫ��ȡ���ֽ���*/
		&offset,/*Ҫ��ȡ���ļ�λ��*/
		NULL);
	if (status == STATUS_SUCCESS)
		*read = isb.Information;
	return status;
}

NTSTATUS writeFile(HANDLE hFile,
	ULONG offsetLow,
	ULONG offsetHig,
	ULONG sizeToWrite,
	PVOID pBuff,
	ULONG* write)
{

	NTSTATUS status;
	IO_STATUS_BLOCK isb = { 0 };
	LARGE_INTEGER offset;
	// ����Ҫд����ļ�ƫ��
	offset.HighPart = offsetHig;
	offset.LowPart = offsetLow;

	status = ZwWriteFile(hFile,/*�ļ����*/
		NULL, /*�¼�����,�û��첽IO*/
		NULL,/*APC����,�����첽IO*/
		NULL, /*APC����*/
		&isb,/*IO״̬*/
		pBuff,/*д�뵽�ļ��еĻ�����*/
		sizeToWrite,/*д����ֽ���*/
		&offset,/*д�뵽���ļ�ƫ��*/
		NULL);
	if (status == STATUS_SUCCESS)
		*write = isb.Information;

	return status;
}

NTSTATUS copyFile(wchar_t* srcPath,
	wchar_t* destPath)
{
	HANDLE hSrc = (HANDLE)-1;
	HANDLE hDest = (HANDLE)-1;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG64 srcSize = 0;
	ULONG	size = 0;
	char*   pBuff = NULL;
	__try
	{
		// 1. �ȴ�Դ�ļ�
		status = createFile(srcPath,
			GENERIC_READ,
			FILE_SHARE_READ,
			FILE_OPEN_IF,
			FALSE,
			&hSrc);

		if (STATUS_SUCCESS != status)
		{
			__leave;
		}


		// 2. ��ȡԴ�ļ���С
		if (STATUS_SUCCESS != getFileSize(hSrc, &srcSize))
		{
			__leave;
		}

		// 3. �����ڴ�ռ䱣��Դ�ļ�������
		pBuff = ExAllocatePool(PagedPool, (ULONG)srcSize);
		if (pBuff == NULL)
		{
			__leave;
		}

		// 3. ��ȡԴ�ļ������ݵ��ڴ���.
		status = readFile(hSrc, 0, 0, (ULONG)srcSize, pBuff, &size);
		if (STATUS_SUCCESS != status || size != (ULONG)srcSize)
		{
			__leave;
		}

		// 4. ��Ŀ���ļ�
		status = createFile(destPath,
			GENERIC_WRITE,
			FILE_SHARE_READ,
			FILE_CREATE,
			FALSE,
			&hDest);
		if (STATUS_SUCCESS != status)
		{
			__leave;
		}

		// 5. ��Դ�ļ�������д�뵽Ŀ���ļ�
		status = writeFile(hDest, 0, 0, (ULONG)srcSize, pBuff, &size);
		if (STATUS_SUCCESS != status || size != srcSize)
		{
			__leave;
		}
		status = STATUS_SUCCESS;
	}
	__finally
	{
		// 6. �ر�Դ�ļ�
		if (hSrc != (HANDLE)-1)
		{
			ZwClose(hSrc);
		}

		// 7. �ر�Ŀ���ļ�
		if (hDest != (HANDLE)-1)
		{
			ZwClose(hDest);
		}

		// 8. �ͷŻ�����
		if (pBuff)
		{
			ExFreePool(pBuff);
		}
	}
	return status;
}

NTSTATUS moveFile(wchar_t* srcPath, wchar_t* destPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	// 1. ����һ���ļ�
	status = copyFile(srcPath, destPath);

	// 2. ��������ɹ���,ɾ��Դ�ļ�
	if (status == STATUS_SUCCESS)
	{
		status = removeFile(srcPath);
	}
	return status;
}

NTSTATUS removeFile(wchar_t* filepath)
{

	UNICODE_STRING path;
	RtlInitUnicodeString(&path, filepath);

	// 1. ��ʼ��OBJECT_ATTRIBUTES������
	OBJECT_ATTRIBUTES objAttrib = { 0 };
	ULONG             ulAttributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	InitializeObjectAttributes(&objAttrib,    // ���س�ʼ����ϵĽṹ��
		&path,		  // �ļ���������
		ulAttributes,  // ��������
		NULL,          // ��Ŀ¼(һ��ΪNULL)
		NULL);         // ��ȫ����(һ��ΪNULL)
// 2. ɾ��ָ���ļ�/�ļ���
	return ZwDeleteFile(&objAttrib);
}


NTSTATUS listDirGet(wchar_t* dir, FILE_BOTH_DIR_INFORMATION** fileInfo, ULONG maxFileCount)
{
	NTSTATUS status = STATUS_SUCCESS;
	IO_STATUS_BLOCK isb = { 0 };
	HANDLE		 hDir = (HANDLE)-1;
	VOID*		pBuff = NULL;
	__try {
		// 1. ��Ŀ¼
		status = createFile(dir,
			GENERIC_READ,
			FILE_SHARE_READ,
			FILE_OPEN_IF,
			TRUE,
			&hDir);
		if (STATUS_SUCCESS != status)
			__leave;

		// ���������һ���ļ���Ϣ���������ֽ��� = �ṹ���С + �ļ�����С
		ULONG signalFileInfoSize = sizeof(FILE_BOTH_DIR_INFORMATION) + 267 * 2;
		// ������ܿռ��ֽ���
		ULONG totalSize = signalFileInfoSize * maxFileCount;

		// �����ڴ�ռ�
		pBuff = ExAllocatePool(PagedPool, totalSize);
		if (pBuff == NULL)
			__leave;

		// ��һ�ε���,��ȡ���軺�����ֽ���
		status = ZwQueryDirectoryFile(hDir, /*Ŀ¼���*/
			NULL, /*�¼�����*/
			NULL, /*���֪ͨ����*/
			NULL, /*���֪ͨ���̸��Ӳ���*/
			&isb, /*IO״̬*/
			pBuff, /*������ļ���Ϣ*/
			totalSize,/*�ļ���Ϣ���������ֽ���*/
			FileBothDirectoryInformation,/*��ȡ��Ϣ������*/
			FALSE,/*�Ƿ�ֻ��ȡ��һ��*/
			0,
			TRUE/*�Ƿ�����ɨ��Ŀ¼*/);
		// ���滺�����������׵�ַ.
		if (status == STATUS_SUCCESS)
			*fileInfo = (FILE_BOTH_DIR_INFORMATION*)pBuff;
	}
	__finally {

		if (hDir != (HANDLE)-1)
		{
			ZwClose(hDir);
		}
		if (status != STATUS_SUCCESS && pBuff != NULL)
		{
			ExFreePool(pBuff);
		}
	}
	return status;
}

NTSTATUS firstFile(wchar_t* dir, HANDLE* hFind, FILE_BOTH_DIR_INFORMATION* fileInfo, int size)
{
	NTSTATUS status = STATUS_SUCCESS;
	IO_STATUS_BLOCK isb = { 0 };
	// 1. ��Ŀ¼
	status = createFile(dir,
		GENERIC_READ,
		FILE_SHARE_READ,
		FILE_OPEN_IF,
		TRUE,
		hFind);
	if (STATUS_SUCCESS != status)
		return status;

	// ��һ�ε���,��ȡ���軺�����ֽ���
	status = ZwQueryDirectoryFile(*hFind, /*Ŀ¼���*/
		NULL, /*�¼�����*/
		NULL, /*���֪ͨ����*/
		NULL, /*���֪ͨ���̸��Ӳ���*/
		&isb, /*IO״̬*/
		fileInfo, /*������ļ���Ϣ*/
		size,/*�ļ���Ϣ���������ֽ���*/
		FileBothDirectoryInformation,/*��ȡ��Ϣ������*/
		TRUE,/*�Ƿ�ֻ��ȡ��һ��*/
		0,
		TRUE/*�Ƿ�����ɨ��Ŀ¼*/);

	return status;
}

NTSTATUS nextFile(HANDLE hFind, FILE_BOTH_DIR_INFORMATION* fileInfo, int size)
{
	IO_STATUS_BLOCK isb = { 0 };
	// ��һ�ε���,��ȡ���軺�����ֽ���
	return ZwQueryDirectoryFile(hFind, /*Ŀ¼���*/
		NULL, /*�¼�����*/
		NULL, /*���֪ͨ����*/
		NULL, /*���֪ͨ���̸��Ӳ���*/
		&isb, /*IO״̬*/
		fileInfo, /*������ļ���Ϣ*/
		size,/*�ļ���Ϣ���������ֽ���*/
		FileBothDirectoryInformation,/*��ȡ��Ϣ������*/
		TRUE,/*�Ƿ�ֻ��ȡ��һ��*/
		0,
		FALSE/*�Ƿ�����ɨ��Ŀ¼*/);
}

void listDirFree(FILE_BOTH_DIR_INFORMATION* fileInfo)
{
	ExFreePool(fileInfo);
}


