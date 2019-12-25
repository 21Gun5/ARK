// CDlgGDT.cpp: 实现文件
//

#include "stdafx.h"
#include "ARK_r3.h"
#include "CDlgGDT.h"
#include "afxdialogex.h"
#include "Tools.h"


// CDlgGDT 对话框

IMPLEMENT_DYNAMIC(CDlgGDT, CDialogEx)

CDlgGDT::CDlgGDT(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_GDT, pParent)
{

}

CDlgGDT::~CDlgGDT()
{
}

void CDlgGDT::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_list);
}


BEGIN_MESSAGE_MAP(CDlgGDT, CDialogEx)
END_MESSAGE_MAP()


// CDlgGDT 消息处理程序


BOOL CDlgGDT::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	// TODO:  在此添加额外的初始化


		// 设置扩展风格
	m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	// 插入列
	m_list.InsertColumn(0, _TEXT("index"), 0, 40);
	m_list.InsertColumn(1, _TEXT("Base"), 0, 80);
	m_list.InsertColumn(2, _TEXT("Limit"), 0, 80);
	m_list.InsertColumn(3, _TEXT("P"), 0, 20);
	m_list.InsertColumn(4, _TEXT("G"), 0, 20);
	m_list.InsertColumn(5, _TEXT("S"), 0, 20);
	m_list.InsertColumn(6, _TEXT("Type"), 0, 40);
	m_list.InsertColumn(7, _TEXT("D/B"), 0, 40);
	m_list.InsertColumn(8, _TEXT("DPL"), 0, 40);

	// 0环获取0x100条数据,故不用事先确定个数
	DWORD size = 0;
	PGDTINFO pGDTInfo = new GDTINFO[0x100 * sizeof(GDTINFO)]{ 0 };// 申请堆空间,并初始化为0
	DeviceIoControl(g_hDev, enumGDT1, NULL, 0, pGDTInfo, 0x100 * sizeof(GDTINFO), &size, NULL);
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
		tmp.Format(_TEXT("%08X"), pGDTInfo->Base);
		m_list.SetItemText(index, 1, tmp);
		tmp.Format(_TEXT("%d"), pGDTInfo->Limit);
		m_list.SetItemText(index, 2, tmp);
		tmp.Format(_TEXT("%d"), pGDTInfo->P);
		m_list.SetItemText(index, 3, tmp);
		tmp.Format(_TEXT("%d"), pGDTInfo->G);
		m_list.SetItemText(index, 4, tmp);
		tmp.Format(_TEXT("%d"), pGDTInfo->S);
		m_list.SetItemText(index, 5, tmp);
		tmp.Format(_TEXT("%d"), pGDTInfo->Type);
		m_list.SetItemText(index, 6, tmp);
		tmp.Format(_TEXT("%d"), pGDTInfo->D_B);
		m_list.SetItemText(index, 7, tmp);
		tmp.Format(_TEXT("%d"), pGDTInfo->DPL);
		m_list.SetItemText(index, 8, tmp);

		// 下一行 下一驱动
		pGDTInfo++;
		index++;
	}


	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}
