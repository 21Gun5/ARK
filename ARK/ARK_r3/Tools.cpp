#include "stdafx.h"
#include "Tools.h"

HANDLE g_hDev = NULL;

//// ��DeviceIoControl�ķ�װ.
//void ark_readprocmemroy(HANDLE hDev, int pid, char* dest, int size)
//{
//	DWORD ret;
//	DeviceIoControl(
//		hDev,
//		readProcessMemory,/*������*/
//		&pid,/*���뻺����:���͸��ں��豸������*/
//		sizeof(DWORD),/*���뻺�������ֽ���*/
//		dest,/*���������*/
//		size,/*������������ֽ���*/
//		&ret,/*ʵ����ɵ��ֽ�*/
//		NULL);
//}