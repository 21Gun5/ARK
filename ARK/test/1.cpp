//#include <stdio.h>
//#include <time.h>
//#include <stdlib.h>
//#include <processthreadsapi.h>
//#include <process.h>
//#include <Tlhelp32.h>
//#include <windows.h>
//
//
//DWORD GetProcessIDByName(const char* pName)
//{
//	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//	if (INVALID_HANDLE_VALUE == hSnapshot) {
//		return NULL;
//	}
//	PROCESSENTRY32 pe = { sizeof(pe) };
//	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
//		if (strcmp(pe.szExeFile, pName) == 0) {
//			CloseHandle(hSnapshot);
//			return pe.th32ProcessID;
//		}
//		//printf("%-6d %s\n", pe.th32ProcessID, pe.szExeFile);
//	}
//	CloseHandle(hSnapshot);
//	return 0;
//}
//
//int main()
//{
//	//time_t t1 = 131196082722361225;
//	//1654050697
//
//	//struct tm *p1 = NULL;
//	//gmtime_s(p1, &t1);
//	//char s1[100];
//	//strftime(s1, sizeof(s1), "%04Y-%02m-%02d %H:%M:%S", p1);
//
//
//	//tm datetime;
//	//time_t seconds = (time_t)1654050697;//自1900年1月1日 00：00：00至此刻的秒数
//	//localtime_s(&datetime, &seconds);
//	////gmtime_s(&datetime, &seconds);
//
//	//char timeBuffer[64];
//	//strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", &datetime);
//
//	//printf("%s", timeBuffer);
//
//
//
//	//int i = GetCurrentProcessId();
//	//int i = getpid();
//	int pid = GetProcessIDByName("notepad++.exe");
//	system("pause");
//}

//#include <windows.h>
//#include <stdint.h>
//#include <tlhelp32.h>
//#include <stdio.h>
//#include <iostream>
//#include <vector>
//
//typedef struct EnumHWndsArg
//{
//	std::vector<HWND> *vecHWnds;
//	DWORD dwProcessId;
//}EnumHWndsArg, *LPEnumHWndsArg;
//
//HANDLE GetProcessHandleByID(int nID)//通过进程ID获取进程句柄
//{
//	return OpenProcess(PROCESS_ALL_ACCESS, FALSE, nID);
//}
//
//DWORD GetProcessIDByName(const char* pName)
//{
//	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//	if (INVALID_HANDLE_VALUE == hSnapshot) {
//		return NULL;
//	}
//	PROCESSENTRY32 pe = { sizeof(pe) };
//	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
//		if (strcmp(pe.szExeFile, pName) == 0) {
//			CloseHandle(hSnapshot);
//			return pe.th32ProcessID;
//		}
//		//printf("%-6d %s\n", pe.th32ProcessID, pe.szExeFile);
//	}
//	CloseHandle(hSnapshot);
//	return 0;
//}
//
//
//
//
//BOOL CALLBACK lpEnumFunc(HWND hwnd, LPARAM lParam)
//{
//	EnumHWndsArg *pArg = (LPEnumHWndsArg)lParam;
//	DWORD  processId;
//	GetWindowThreadProcessId(hwnd, &processId);
//	if (processId == pArg->dwProcessId)
//	{
//		pArg->vecHWnds->push_back(hwnd);
//		//printf("%p\n", hwnd);
//	}
//	return TRUE;
//}
//
//void GetHWndsByProcessID(DWORD processID, std::vector<HWND> &vecHWnds)
//{
//	EnumHWndsArg wi;
//	wi.dwProcessId = processID;
//	wi.vecHWnds = &vecHWnds;
//	EnumWindows(lpEnumFunc, (LPARAM)&wi);
//}
//
//int32_t main()
//{
//	DWORD pid = GetProcessIDByName("notepad++.exe");
//	printf("pid = %u\n", pid);
//	if (pid != 0)
//	{
//		std::vector<HWND> vecHWnds;
//		GetHWndsByProcessID(pid, vecHWnds);
//		printf("vecHWnds.size() = %u\n", vecHWnds.size());
//		for (const HWND &h : vecHWnds)
//		{
//			HWND parent = GetParent(h);
//			if (parent == NULL)
//			{
//				printf("%p --->Main Wnd\n", h);
//			}
//			else
//			{
//				printf("%p %p\n", h, parent);
//			}
//		}
//	}
//	getchar();
//	return S_OK;
//}


//#ifdef _WIN32
#include <process.h>
//#else
//#include <unistd.h>
//#endif
int main()
{
	int iPid = (int)_getpid();
	//std::cout << "The process id is: " << iPid << std::endl;
	return 0;
}