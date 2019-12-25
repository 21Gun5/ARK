// CDlgThread.cpp: 实现文件
//

#include "stdafx.h"
#include "ARK_r3.h"
#include "CDlgThread.h"
#include "afxdialogex.h"
#include "Tools.h"


// CDlgThread 对话框

IMPLEMENT_DYNAMIC(CDlgThread, CDialogEx)

CDlgThread::CDlgThread(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_THREAD, pParent)
{

}

CDlgThread::~CDlgThread()
{
}

void CDlgThread::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_list);
}


BEGIN_MESSAGE_MAP(CDlgThread, CDialogEx)
END_MESSAGE_MAP()


// CDlgThread 消息处理程序


BOOL CDlgThread::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化


	// 设置扩展风格
	m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	// 插入列
	m_list.InsertColumn(0, _TEXT("index"), 0, 40);
	m_list.InsertColumn(1, _TEXT("TID"), 0, 80);


	// 第一次,确定有多少个
	DWORD size = 0;
	DWORD count = 0;
	DeviceIoControl(g_hDev, enumThread1, &m_curProcIndex, sizeof(DWORD), &count, sizeof(DWORD), &size, NULL);
	//CString tmp;
	//tmp.Format(_TEXT("%d"), count);
	//MessageBox(tmp);

	// 第二次,获取所有数据
	PTHREADINFO pThreadInfo = new THREADINFO[count * sizeof(THREADINFO)]{ 0 };// 申请堆空间,并初始化为0
	DeviceIoControl(g_hDev, enumThread2, &m_curProcIndex, sizeof(DWORD), pThreadInfo, count * sizeof(THREADINFO), &size, NULL);
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
		tmp.Format(_TEXT("%d"), pThreadInfo->TID);
		m_list.SetItemText(index, 1, tmp);
		// 下一行 下一驱动
		pThreadInfo++;
		index++;
	}


	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}


void CDlgThread::SetCurProcessIndex(DWORD index)
{
	// TODO: 在此处添加实现代码.
	m_curProcIndex = index;
}
