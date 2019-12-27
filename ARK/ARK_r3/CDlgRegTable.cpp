// CDlgRegTable.cpp: 实现文件
//

#include "stdafx.h"
#include "ARK_r3.h"
#include "CDlgRegTable.h"
#include "afxdialogex.h"
#include "Tools.h"


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
	DDX_Control(pDX, IDC_TREE1, m_tree);
}


BEGIN_MESSAGE_MAP(CDlgRegTable, CDialogEx)
END_MESSAGE_MAP()


// CDlgRegTable 消息处理程序

BOOL CDlgRegTable::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化

	// 对树控件进行操作，参数二不写就是添加到最外层
	HTREEITEM RootNode = m_tree.InsertItem(_TEXT("Registry"));
	HTREEITEM SubNode1 = m_tree.InsertItem(L"A", RootNode);
	HTREEITEM SubNode2 = m_tree.InsertItem(L"MACHINE", RootNode);
	HTREEITEM SubNode3 = m_tree.InsertItem(L"USER", RootNode);

	// 遍历根节点下三个子节点
	DWORD size = 0;
	for (DWORD i = 0; i < 3; i++)
	{
		// 第一次,确定有多少个
		DWORD count = 0;
		DeviceIoControl(g_hDev, enumRegTable1, &i, sizeof(DWORD), &count, sizeof(DWORD), &size, NULL);
		//CString tmp;
		//tmp.Format(_TEXT("%d"), count);
		//MessageBox(tmp);

		// 第二次,获取所有数据
		PREGTABLEINFO pRegTableInfo = new REGTABLEINFO[count * sizeof(REGTABLEINFO)]{ 0 };
		DeviceIoControl(g_hDev, enumRegTable2, &i, sizeof(DWORD), pRegTableInfo, count * sizeof(REGTABLEINFO), &size, NULL);
		// 循环插入
		for (DWORD j = 0; j < count; j++)//count-1,0环 do-while 多加一个
		{
			CString tmp;
			tmp.Format(_TEXT("%s"), pRegTableInfo->name);
			switch (i)
			{
			case 0:
				m_tree.InsertItem(tmp, SubNode1);
				break;
			case 1:
				m_tree.InsertItem(tmp, SubNode2);
				break;
			case 2:
				m_tree.InsertItem(tmp, SubNode3);
				break;
			default:
				break;
			}
			
			// 下一行 下一驱动
			pRegTableInfo++;
		}

	}

	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}
