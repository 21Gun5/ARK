// CDlgSSDT.cpp: 实现文件
//

#include "stdafx.h"
#include "ARK_r3.h"
#include "CDlgSSDT.h"
#include "afxdialogex.h"
#include "Tools.h"


// CDlgSSDT 对话框

IMPLEMENT_DYNAMIC(CDlgSSDT, CDialogEx)

CDlgSSDT::CDlgSSDT(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_SSDT, pParent)
{

}

CDlgSSDT::~CDlgSSDT()
{
}

void CDlgSSDT::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_list);
}


BEGIN_MESSAGE_MAP(CDlgSSDT, CDialogEx)
END_MESSAGE_MAP()


// CDlgSSDT 消息处理程序


BOOL CDlgSSDT::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化
	
	// 设置扩展风格
	m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	// 插入列
	m_list.InsertColumn(0, _TEXT("index"), 0, 40);
	m_list.InsertColumn(1, _TEXT("FuncAddr"), 0, 100);
	//m_list.InsertColumn(2, _TEXT("ParamCount"), 0, 50);


	// 第一次,确定有多少个
	DWORD size = 0;
	DWORD count = 0;
	DeviceIoControl(g_hDev, enumSSDT1, NULL, 0, &count, sizeof(DWORD), &size, NULL);
	//CString tmp;
	//tmp.Format(_TEXT("%d"), count);
	//MessageBox(tmp);


	// 第二次,获取所有数据
	PSSDTINFO pSSDTInfo = new SSDTINFO[count * sizeof(SSDTINFO)]{ 0 };// 申请堆空间,并初始化为0
	DeviceIoControl(g_hDev, enumSSDT2, NULL, 0, pSSDTInfo, count * sizeof(SSDTINFO), &size, NULL);
	// 循环插入
	DWORD index = 0;
	for (DWORD i = 0; i < count; i++)//count-1,0环 do-while 多加一个
	{
		CString tmp;
		// 插入行
		m_list.InsertItem(index, _TEXT(""));
		// 插入数据
		tmp.Format(_TEXT("%d"), i);
		m_list.SetItemText(index, 0, tmp);
		tmp.Format(_TEXT("%08X"), pSSDTInfo->funcAddr);
		m_list.SetItemText(index, 1, tmp);
		// 下一行 下一驱动
		pSSDTInfo++;
		index++;
	}

	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}
