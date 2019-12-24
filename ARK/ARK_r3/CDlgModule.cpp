// CDlgModule.cpp: 实现文件
//

#include "stdafx.h"
#include "ARK_r3.h"
#include "CDlgModule.h"
#include "afxdialogex.h"
#include "Tools.h"


// CDlgModule 对话框

IMPLEMENT_DYNAMIC(CDlgModule, CDialogEx)

CDlgModule::CDlgModule(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_MODULE, pParent)
{

}

CDlgModule::~CDlgModule()
{
}

void CDlgModule::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_list);
}


BEGIN_MESSAGE_MAP(CDlgModule, CDialogEx)
END_MESSAGE_MAP()


// CDlgModule 消息处理程序


void CDlgModule::SetCurProcessIndex(DWORD index)
{
	// TODO: 在此处添加实现代码.
	m_curProcIndex = index;
}


BOOL CDlgModule::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化

	// 设置扩展风格
	m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	// 插入列
	m_list.InsertColumn(0, _TEXT("index"), 0, 40);
	m_list.InsertColumn(1, _TEXT("基址"), 0, 70);
	m_list.InsertColumn(2, _TEXT("大小"), 0, 60);
	m_list.InsertColumn(3, _TEXT("路径"), 0, 400);

	// 第一次,确定有多少个
	DWORD size = 0;
	DWORD count = 0;
	DeviceIoControl(g_hDev, enumModule1, &m_curProcIndex, sizeof(DWORD), &count, sizeof(DWORD), &size, NULL);
	//CString tmp;
	//tmp.Format(_TEXT("%d"), count);
	//MessageBox(tmp);

	// 第二次,获取所有数据
	PDRIVERINFO pModuleInfo = new DRIVERINFO[count * sizeof(MODULEINFO)]{ 0 };// 申请堆空间,并初始化为0
	DeviceIoControl(g_hDev, enumModule2, &m_curProcIndex, sizeof(DWORD), pModuleInfo, count * sizeof(MODULEINFO), &size, NULL);
	// 循环插入
	DWORD index = 0;
	for (DWORD i = 0; i < count - 1; i++)//count-1,0环 do-while 多加一个
	{
		CString tmp;
		// 插入行
		m_list.InsertItem(index, _TEXT(""));
		// 插入数据
		tmp.Format(_TEXT("%d"), i);
		m_list.SetItemText(index, 0, tmp);
		tmp.Format(_TEXT("%08X"), pModuleInfo->base);
		m_list.SetItemText(index, 1, tmp);
		tmp.Format(_TEXT("%06X"), pModuleInfo->size);
		m_list.SetItemText(index, 2, tmp);
		tmp.Format(_TEXT("%s"), pModuleInfo->name);
		m_list.SetItemText(index, 3, tmp);
		// 下一行 下一驱动
		pModuleInfo++;
		index++;
	}

	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}
