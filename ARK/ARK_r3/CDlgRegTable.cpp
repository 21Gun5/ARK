// CDlgRegTable.cpp: 实现文件
//

#include "stdafx.h"
#include "ARK_r3.h"
#include "CDlgRegTable.h"
#include "afxdialogex.h"


// CDlgRegTable 对话框

IMPLEMENT_DYNAMIC(CDlgRegTable, CDialogEx)

CDlgRegTable::CDlgRegTable(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_REGTABLE, pParent)
{

}

CDlgRegTable::~CDlgRegTable()
{
}

void CDlgRegTable::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CDlgRegTable, CDialogEx)
END_MESSAGE_MAP()


// CDlgRegTable 消息处理程序
