// CDlgThread.cpp: 实现文件
//

#include "stdafx.h"
#include "ARK_r3.h"
#include "CDlgThread.h"
#include "afxdialogex.h"


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
}


BEGIN_MESSAGE_MAP(CDlgThread, CDialogEx)
END_MESSAGE_MAP()


// CDlgThread 消息处理程序
