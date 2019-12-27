#pragma once
#include <ntifs.h>
#include <ntddk.h>

//////////////////////////////////////////////////////////////////////////
//////////////////////////// �ڴ���� /////////////////////////////////////

//************************************
// Method:    alloc �����ڴ�
// Returns:   void* �����ڴ�ռ��׵�ַ, ����ʧ�ܷ���NULL
// Parameter: ULONG size Ҫ������ֽ���
//************************************
void* alloc(ULONG size);
//************************************
// Method:    reAlloc ���·���ռ�
// Returns:   void*  �����¿ռ���ڴ��ַ
// Parameter: void * src ԭʼ�ڴ�ռ�(������alloc����������)
// Parameter: ULONG size ���·�����ֽ���
//************************************
void* reAlloc(void* src, ULONG size);

//************************************
// Method:    free �ͷ��ڴ�ռ�
// Returns:   void
// Parameter: void *
//************************************
//void free(void* data);



//////////////////////////////////////////////////////////////////////////
//////////////////////////// �ļ����� /////////////////////////////////////
//************************************
// Method:    createFile �����ļ�
// Returns:   NTSTATUS
// Parameter: const wchar_t * filepath �ļ�·��,·���������豸��"\\device\\volumn\\"�����������"\\??\\C:\\1.txt"
// Parameter: ULONG access ����Ȩ��, GENERIC_READ, GENERIC_XXX
// Parameter: ULONG share �ļ�����ʽ: FILE_SHARE_XXX
// Parameter: ULONG openModel  �򿪷�ʽ: FILE_OPEN_IF,FILE_CREATE ...
// Parameter: BOOLEAN isDir �Ƿ�ΪĿ¼
// Parameter: HANDLE * hFile
//************************************
NTSTATUS createFile(wchar_t* filepath,
	ULONG access,
	ULONG share,
	ULONG openModel,
	BOOLEAN isDir,
	HANDLE* hFile);

//************************************
// Method:    getFileSize ��ȡ�ļ���С
// Returns:   NTSTATUS  
// Parameter: HANDLE hFile �ļ����
// Parameter: ULONG64 * size  �ļ���С
//************************************
NTSTATUS getFileSize(HANDLE hFile,
	ULONG64* size);

//************************************
// Method:    readFile  ��ȡ�ļ�����
// Returns:   NTSTATUS
// Parameter: HANDLE hFile �ļ����
// Parameter: ULONG offsetLow �ļ�ƫ�Ƶĵ�32λ, �Ӵ�λ�ÿ�ʼ��ȡ
// Parameter: ULONG offsetHig �ļ�ƫ�Ƶĸ�32λ, �Ӵ�λ�ÿ�ʼ��ȡ
// Parameter: ULONG sizeToRead Ҫ��ȡ���ֽ���
// Parameter: PVOID pBuff �����ļ����ݵĻ����� , ��Ҫ�Լ������ڴ�ռ�.
// Parameter: ULONG * read ʵ�ʶ�ȡ�����ֽ���
//************************************
NTSTATUS readFile(HANDLE hFile,
	ULONG offsetLow,
	ULONG offsetHig,
	ULONG sizeToRead,
	PVOID pBuff,
	ULONG* read);

NTSTATUS writeFile(HANDLE hFile,
	ULONG offsetLow,
	ULONG offsetHig,
	ULONG sizeToWrite,
	PVOID pBuff,
	ULONG* write);

NTSTATUS copyFile(wchar_t* srcPath,
	wchar_t* destPath);

NTSTATUS moveFile(wchar_t* srcPath,
	wchar_t* destPath);

NTSTATUS removeFile(wchar_t* path);


//************************************
// Method:    listDirGet �г�һ��Ŀ¼�µ��ļ����ļ���
// Returns:   NTSTATUS 
// Parameter: wchar_t * dir Ŀ¼��, Ŀ¼���������豸��"\\device\\volumn\\"�����������"\\??\\C:\\1.txt"
// Parameter: FILE_BOTH_DIR_INFORMATION ** fileInfo �����ļ����ݵĻ�����, �û������ɺ����ڲ�����ռ�, ����ͨ������`listDirFree`���ͷ�.
// Parameter: ULONG maxFileCount Ҫ��ȡ������ļ�����.���Ŀ¼����100���ļ�,�˲�������5,��ֻ�ܻ�ȡ��5���ļ�.
//************************************
NTSTATUS listDirGet(wchar_t* dir,
	FILE_BOTH_DIR_INFORMATION** fileInfo,
	ULONG maxFileCount);



//************************************
// Method:    firstFile ��ȡһ��Ŀ¼�µĵ�һ���ļ�
// Returns:   NTSTATUS
// Parameter: wchar_t * dir Ŀ¼��, Ŀ¼���������豸��"\\device\\volumn\\"�����������"\\??\\C:\\1.txt"
// Parameter: HANDLE * hFind �������ֵ,��һ��Ŀ¼���
// Parameter: FILE_BOTH_DIR_INFORMATION * fileInfo �����ļ����ݵĻ�����, 
//								����������Ĵ�С�����: sizeof(FILE_BOTH_DIR_INFORMATION) + 267*2
//************************************
NTSTATUS firstFile(wchar_t* dir, HANDLE* hFind, FILE_BOTH_DIR_INFORMATION* fileInfo, int size);

//************************************
// Method:    nextFile ��ȡһ��Ŀ¼�µ���һ���ļ�. 
// Returns:   NTSTATUS
// Parameter: HANDLE hFind  Ŀ¼���, �þ������firstFile���������� .
// Parameter: FILE_BOTH_DIR_INFORMATION * fileInfo �����ļ���Ϣ�Ļ�����. ����������Ĵ�С�����: sizeof(FILE_BOTH_DIR_INFORMATION) + 267*2
//************************************
NTSTATUS nextFile(HANDLE hFind, FILE_BOTH_DIR_INFORMATION* fileInfo, int size);


void listDirFree(FILE_BOTH_DIR_INFORMATION* fileInfo);

#define ListDirNext(Type,fileinfo) ((Type*)((ULONG_PTR)fileinfo + fileinfo->NextEntryOffset))
#define ListDirForEach(FileInfoType,fileInfo, iterator) \
	for (FileInfoType* iterator = fileInfo; \
		iterator->NextEntryOffset != 0;	 \
		iterator = ListDirNext(FileInfoType,iterator))


#pragma pack(1)
typedef struct _ServiceDesriptorEntry
{
	ULONG *ServiceTableBase;        // ������ַ
	ULONG *ServiceCounterTableBase; // �������ַ
	ULONG NumberOfServices;         // ������ĸ���
	UCHAR *ParamTableBase;          // �������ַ
}SSDTEntry, *PSSDTEntry;
#pragma pack()

//typedef struct _LDR_DATA_TABLE_ENTRY
//{
//	LIST_ENTRY InLoadOrderLinks;    //˫������
//	LIST_ENTRY InMemoryOrderLinks;
//	LIST_ENTRY InInitializationOrderLinks;
//	PVOID DllBase;
//	PVOID EntryPoint;
//	ULONG SizeOfImage;
//	UNICODE_STRING FullDllName;
//	UNICODE_STRING BaseDllName;
//	ULONG Flags;
//	USHORT LoadCount;
//	USHORT TlsIndex;
//	// ...
//} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


void disablePageWriteProtect();
void enablePageWriteProtect();
VOID DriverUnload(PDRIVER_OBJECT pDriver);