// CDlgIDT.cpp: 实现文件
//

#include "stdafx.h"
#include "ARK_r3.h"
#include "CDlgIDT.h"
#include "afxdialogex.h"
#include "Tools.h"


// CDlgIDT 对话框

IMPLEMENT_DYNAMIC(CDlgIDT, CDialogEx)

CDlgIDT::CDlgIDT(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_IDT, pParent)
{

}

CDlgIDT::~CDlgIDT()
{
}

void CDlgIDT::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_list);
}


BEGIN_MESSAGE_MAP(CDlgIDT, CDialogEx)
END_MESSAGE_MAP()


// CDlgIDT 消息处理程序

BOOL CDlgIDT::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化

	// 设置扩展风格
	m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	// 插入列
	m_list.InsertColumn(0, _TEXT("index"), 0, 40);
	m_list.InsertColumn(1, _TEXT("Address"), 0, 80);
	m_list.InsertColumn(2, _TEXT("Selector"), 0, 80);
	m_list.InsertColumn(3, _TEXT("GateType"), 0, 80);
	m_list.InsertColumn(4, _TEXT("DPL"), 0, 40);

	// 0环获取0x100条数据,故不用事先确定个数
	DWORD size = 0;
	PIDTINFO pIDTInfo = new IDTINFO[0x100* sizeof(IDTINFO)]{ 0 };// 申请堆空间,并初始化为0
	DeviceIoControl(g_hDev, enumIDT1, NULL, 0, pIDTInfo, 0x100 * sizeof(IDTINFO), &size, NULL);
	// 循环插入
	DWORD index = 0;
	for (DWORD i = 0; i < 0x100; i++)
	{
		CString tmp;
		// 插入行
		m_list.InsertItem(index, _TEXT(""));
		// 插入数据
		tmp.Format(_TEXT("%d"), i);
		m_list.SetItemText(index, 0, tmp);
		tmp.Format(_TEXT("%08X"), pIDTInfo->addr);
		m_list.SetItemText(index, 1, tmp);
		tmp.Format(_TEXT("%d"), pIDTInfo->uSelector);
		m_list.SetItemText(index, 2, tmp);
		tmp.Format(_TEXT("%d"), pIDTInfo->GateType);
		m_list.SetItemText(index, 3, tmp);
		tmp.Format(_TEXT("%d"), pIDTInfo->DPL);
		m_list.SetItemText(index, 4, tmp);
		// 下一行 下一驱动
		pIDTInfo++;
		index++;
	}


	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}
