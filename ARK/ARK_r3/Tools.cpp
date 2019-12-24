#include "stdafx.h"
#include "Tools.h"

HANDLE g_hDev = NULL;

//// 对DeviceIoControl的封装.
//void ark_readprocmemroy(HANDLE hDev, int pid, char* dest, int size)
//{
//	DWORD ret;
//	DeviceIoControl(
//		hDev,
//		readProcessMemory,/*控制码*/
//		&pid,/*输入缓冲区:传送给内核设备的数据*/
//		sizeof(DWORD),/*输入缓冲区的字节数*/
//		dest,/*输出缓冲区*/
//		size,/*输出缓冲区的字节数*/
//		&ret,/*实际完成的字节*/
//		NULL);
//}