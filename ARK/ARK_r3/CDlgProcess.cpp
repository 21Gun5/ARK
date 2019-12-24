// CDlgProcess.cpp: 实现文件
//

#include "stdafx.h"
#include "ARK_r3.h"
#include "CDlgProcess.h"
#include "afxdialogex.h"


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
}


BEGIN_MESSAGE_MAP(CDlgProcess, CDialogEx)
	//ON_BN_CLICKED(IDC_BUTTON1, &CDlgProcess::OnBnClickedButton1)
END_MESSAGE_MAP()


// CDlgProcess 消息处理程序


BOOL CDlgProcess::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化




	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}


//void CDlgProcess::OnBnClickedButton1()
//{
//	// TODO: 在此添加控件通知处理程序代码
//
//	TCHAR buff[100];
//	DWORD size = 0;
//	DWORD count = 0;
//	// 第一次,确定有多少个
//	DeviceIoControl(g_hDev, listDriver, NULL, 0, NULL, 0, &size, NULL);
//}
