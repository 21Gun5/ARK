// CDlgProcess.cpp: 实现文件
//

#include "stdafx.h"
#include "ARK_r3.h"
#include "CDlgProcess.h"
#include "afxdialogex.h"
#include "Tools.h"
#include "CDlgModule.h"
#include "CDlgThread.h"


// CDlgProcess 对话框

IMPLEMENT_DYNAMIC(CDlgProcess, CDialogEx)

CDlgProcess::CDlgProcess(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_PROCESS, pParent)
{

}

CDlgProcess::~CDlgProcess()
{
}

void CDlgProcess::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_list);
}

BEGIN_MESSAGE_MAP(CDlgProcess, CDialogEx)
	//ON_BN_CLICKED(IDC_BUTTON1, &CDlgProcess::OnBnClickedButton1)
	ON_COMMAND(ID_KILLPROC, &CDlgProcess::OnKillprocess)
	ON_COMMAND(ID_HIDEPROC, &CDlgProcess::OnHideprocess)
	ON_COMMAND(ID_ENUMTHRE, &CDlgProcess::OnEnumthread)
	ON_COMMAND(ID_ENUMMODU, &CDlgProcess::OnEnummodu)
	ON_NOTIFY(NM_RCLICK, IDC_LIST1, &CDlgProcess::OnRclickList1)
END_MESSAGE_MAP()


// CDlgProcess 消息处理程序


BOOL CDlgProcess::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化

	// 菜单设置
	m_menu.LoadMenu(IDR_MENU1);

	// 设置扩展风格
	m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	// 插入列
	m_list.InsertColumn(0, _TEXT("index"), 0, 40);
	m_list.InsertColumn(1, _TEXT("PID"), 0, 70);
	m_list.InsertColumn(2, _TEXT("Name"), 0, 400);

	// 第一次,确定有多少个
	DWORD size = 0;
	DWORD count = 0;
	DeviceIoControl(g_hDev, enumProcess1, NULL, 0, &count, sizeof(DWORD), &size, NULL);
	// 第二次,获取所有数据
	PPROCESSINFO pProcessInfo = new PROCESSINFO[count * sizeof(PROCESSINFO)]{ 0 };// 申请堆空间,并初始化为0
	DeviceIoControl(g_hDev, enumProcess2, NULL, 0, pProcessInfo, count * sizeof(PROCESSINFO), &size, NULL);
	// 循环插入
	DWORD index = 0;
	for (DWORD i = 0; i < count; i++)
	{
		CString tmp;
		// 插入行
		m_list.InsertItem(index, _TEXT(""));
		// 插入数据
		tmp.Format(_TEXT("%d"), i);
		m_list.SetItemText(index, 0, tmp);
		tmp.Format(_TEXT("%d"), pProcessInfo->PID);
		m_list.SetItemText(index, 1, tmp);
		tmp.Format(_TEXT("%S"), pProcessInfo->name);//用大S,宽字符(驱动时用小s,因二者在0环获取时不同
		m_list.SetItemText(index, 2, tmp);
		// 下一行 下一驱动
		pProcessInfo++;
		index++;
	}

	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}

//void CDlgProcess::OnBnClickedButton1()
//{
//	// TODO: 在此添加控件通知处理程序代码
//
//	// 第一次,确定有多少个
//	DWORD size = 0;
//	DWORD count = 0;
//	DeviceIoControl(g_hDev, enumProcess1, NULL, 0, &count, sizeof(DWORD), &size, NULL);
//	// 第二次,获取所有数据
//	PPROCESSINFO pProcessInfo = new PROCESSINFO[count * sizeof(PROCESSINFO)]{0};// 申请堆空间,并初始化为0
//	DeviceIoControl(g_hDev, enumProcess2, NULL, 0, pProcessInfo, count * sizeof(PROCESSINFO), &size, NULL);
//	// 循环插入
//	DWORD index = 0;
//	for (DWORD i = 0; i < count; i++)
//	{
//		CString tmp;
//		// 插入行
//		m_list.InsertItem(index, _TEXT(""));
//		// 插入数据
//		tmp.Format(_TEXT("%d"), i);
//		m_list.SetItemText(index, 0, tmp);
//		tmp.Format(_TEXT("%d"), pProcessInfo->PID);
//		m_list.SetItemText(index, 1, tmp);
//		tmp.Format(_TEXT("%S"), pProcessInfo->name);//用大S,宽字符(驱动时用小s,因二者在0环获取时不同
//		m_list.SetItemText(index, 2, tmp);
//		// 下一行 下一驱动
//		pProcessInfo++;
//		index++;
//	}
//}


void CDlgProcess::OnKillprocess()
{
	// TODO: 在此添加命令处理程序代码


}


void CDlgProcess::OnHideprocess()
{
	// TODO: 在此添加命令处理程序代码
}


void CDlgProcess::OnEnumthread()
{
	// TODO: 在此添加命令处理程序代码

	// 创建模块对话框
	CDlgThread threadDlg(this);
	// 获取被点击的进程（通过光标选择序号，序号从1开始，故-1
	int index = (int)m_list.GetFirstSelectedItemPosition() - 1;
	// 传递当前进程索引

	threadDlg.SetCurProcessIndex(index);
	// 运行对话框
	threadDlg.DoModal();
}


void CDlgProcess::OnEnummodu()
{
	// TODO: 在此添加命令处理程序代码
	// 创建模块对话框
	CDlgModule moduleDlg(this);
	// 获取被点击的进程（通过光标选择序号，序号从1开始，故-1
	int index = (int)m_list.GetFirstSelectedItemPosition() - 1;
	// 传递当前进程索引
	moduleDlg.SetCurProcessIndex(index);
	// 运行对话框
	moduleDlg.DoModal();
}

void CDlgProcess::OnRclickList1(NMHDR *pNMHDR, LRESULT *pResult)
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
