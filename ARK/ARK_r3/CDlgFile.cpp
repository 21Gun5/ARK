// CDlgFile.cpp: 实现文件
//

#include "stdafx.h"
#include "ARK_r3.h"
#include "CDlgFile.h"
#include "afxdialogex.h"
#include "Tools.h"
#include <time.h>


// CDlgFile 对话框

IMPLEMENT_DYNAMIC(CDlgFile, CDialogEx)

CDlgFile::CDlgFile(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_FILE, pParent)
{

}

CDlgFile::~CDlgFile()
{
}

void CDlgFile::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_list);
}


BEGIN_MESSAGE_MAP(CDlgFile, CDialogEx)
	ON_COMMAND(ID_RENEW, &CDlgFile::OnRenew)
	ON_NOTIFY(NM_RCLICK, IDC_LIST1, &CDlgFile::OnRclickList1)
	ON_COMMAND(ID_DELETEFILE, &CDlgFile::OnDeletefile)
END_MESSAGE_MAP()


// CDlgFile 消息处理程序


BOOL CDlgFile::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化

	// 菜单设置
	m_menu.LoadMenu(IDR_MENU3);

	// 设置扩展风格
	m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	// 插入列
	m_list.InsertColumn(0, _TEXT("index"), 0, 40);
	m_list.InsertColumn(1, _TEXT("文件名"), 0, 150);
	m_list.InsertColumn(2, _TEXT("占用空间"), 0, 60);
	m_list.InsertColumn(3, _TEXT("属性值"), 0, 50);
	m_list.InsertColumn(4, _TEXT("创建时间"), 0, 60);
	m_list.InsertColumn(5, _TEXT("修改时间"), 0, 60);

	OnRenew();

	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}



void CDlgFile::OnRclickList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;

	// 弹出右键菜单
	CMenu* pSubMenu = m_menu.GetSubMenu(0);
	CPoint pos;
	GetCursorPos(&pos);
	pSubMenu->TrackPopupMenu(0, pos.x, pos.y, this);
}

void CDlgFile::OnRenew()
{
	// TODO: 在此添加命令处理程序代码

	// 刷新前先清空所有
	m_list.DeleteAllItems();
	// 第一次,确定有多少个
	DWORD size = 0;
	DWORD count = 0;
	DeviceIoControl(g_hDev, enumFile1, NULL, 0, &count, sizeof(DWORD), &size, NULL);
	//CString tmp;
	//tmp.Format(_TEXT("%d"), count);
	//MessageBox(tmp);

	// 第二次,获取所有数据
	PFILEINFO pFileInfo = new FILEINFO[count * sizeof(FILEINFO)]{ 0 };// 申请堆空间,并初始化为0
	DeviceIoControl(g_hDev, enumFile2, NULL, 0, pFileInfo, count * sizeof(FILEINFO), &size, NULL);
	// 循环插入
	DWORD index = 0;
	for (DWORD i = 0; i < count - 1; i++)//count-1,0环 do-while 多加一个
	{
		CString tmp;
		// 插入行
		m_list.InsertItem(index, _TEXT(""));
		// 插入数据
		tmp.Format(_TEXT("%d"), i);
		m_list.SetItemText(index, 0, tmp);
		// 判断目录/文件
		if(pFileInfo->attribute&FILE_ATTRIBUTE_DIRECTORY)
			tmp.Format(_TEXT("[目录] %s"), pFileInfo->fileName);
		else
			tmp.Format(_TEXT("[文件] %s"), pFileInfo->fileName);
		m_list.SetItemText(index, 1, tmp);
		tmp.Format(_TEXT("%d"), pFileInfo->size);
		m_list.SetItemText(index, 2, tmp);
		tmp.Format(_TEXT("%d"), pFileInfo->attribute);
		m_list.SetItemText(index, 3, tmp);

		FILETIME LocalTime = { 0 };//本地时间
		SYSTEMTIME SysTime;//系统时间
		LocalTime.dwLowDateTime = pFileInfo->createTime.LowPart;
		LocalTime.dwHighDateTime = pFileInfo->createTime.HighPart;
		FileTimeToSystemTime(&LocalTime, &SysTime);
		tmp.Format(_TEXT("%04d-%02d-%02d  %02d:%02d:%02d\n"), SysTime.wYear, SysTime.wMonth, SysTime.wDay, SysTime.wHour, SysTime.wMinute, SysTime.wSecond);
		m_list.SetItemText(index, 4, tmp);

		LocalTime.dwLowDateTime = pFileInfo->changeTime.LowPart;
		LocalTime.dwHighDateTime = pFileInfo->changeTime.HighPart;
		FileTimeToSystemTime(&LocalTime, &SysTime);
		tmp.Format(_TEXT("%04d-%02d-%02d  %02d:%02d:%02d\n"), SysTime.wYear, SysTime.wMonth, SysTime.wDay, SysTime.wHour, SysTime.wMinute, SysTime.wSecond);
		m_list.SetItemText(index, 5, tmp);

		

		// 下一行 下一驱动
		pFileInfo++;
		index++;
	}
}



void CDlgFile::OnDeletefile()
{
	// TODO: 在此添加命令处理程序代码

	// 获取被点击的驱动（通过光标选择序号，序号从1开始，故-1
	DWORD index = (int)m_list.GetFirstSelectedItemPosition() - 1;
	//PFILEINFO pFileInfo = new FILEINFO[sizeof(FILEINFO)]{ 0 };// 申请堆空间,并初始化为0
	//filename = m_list.GetItemText(index, 1);
	DWORD size = 0;
	DeviceIoControl(g_hDev, deleteFile, &index, sizeof(DWORD), NULL, 0, &size, NULL);

}
