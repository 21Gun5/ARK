// CDlgFile.cpp: 实现文件
//

#include "stdafx.h"
#include "ARK_r3.h"
#include "CDlgFile.h"
#include "afxdialogex.h"


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
}


BEGIN_MESSAGE_MAP(CDlgFile, CDialogEx)
END_MESSAGE_MAP()


// CDlgFile 消息处理程序
