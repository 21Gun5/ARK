// CDlgDriver.cpp: 实现文件
//

#include "stdafx.h"
#include "ARK_r3.h"
#include "CDlgDriver.h"
#include "afxdialogex.h"
#include "Tools.h"

// CDlgDriver 对话框

IMPLEMENT_DYNAMIC(CDlgDriver, CDialogEx)

CDlgDriver::CDlgDriver(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG_DRIVER, pParent)
{

}

CDlgDriver::~CDlgDriver()
{
}

void CDlgDriver::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_list);
}

BEGIN_MESSAGE_MAP(CDlgDriver, CDialogEx)
	//ON_BN_CLICKED(IDC_BUTTON2, &CDlgDriver::OnBnClickedButton2)
END_MESSAGE_MAP()


BOOL CDlgDriver::OnInitDialog()
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
	DeviceIoControl(g_hDev, enumDriver1, NULL, 0, &count, sizeof(DWORD), &size, NULL);
	// 第二次,获取所有数据
	PDRIVERINFO pDriverInfo = new DRIVERINFO[count * sizeof(DRIVERINFO)]{ 0 };// 申请堆空间,并初始化为0
	DeviceIoControl(g_hDev, enumDriver2, NULL, 0, pDriverInfo, count * sizeof(DRIVERINFO), &size, NULL);
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
		tmp.Format(_TEXT("%08X"), pDriverInfo->base);
		m_list.SetItemText(index, 1, tmp);
		tmp.Format(_TEXT("%06X"), pDriverInfo->size);
		m_list.SetItemText(index, 2, tmp);
		tmp.Format(_TEXT("%s"), pDriverInfo->name);
		m_list.SetItemText(index, 3, tmp);
		// 下一行 下一驱动
		pDriverInfo++;
		index++;
	}

	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}

// CDlgDriver 消息处理程序


//void CDlgDriver::OnBnClickedButton2()
//{
//	// TODO: 在此添加控件通知处理程序代码
//
//	TCHAR buff[100];
//	DWORD size = 0;
//	DWORD count = 0;
//	// 第一次,确定有多少个
//	DeviceIoControl(g_hDev, listDriver, NULL, 0, NULL, 0, &count, NULL);
//	CString driverCount;
//	driverCount.Format(_TEXT("%d"), count);
//	MessageBox(driverCount);
//	// 第二次,获取所有数据(逐个
//	//DWORD index = 0;
//	DRIVERINFO driverInfo = {0};
//	for (DWORD i = 0; i < 3; i++)
//	{
//		DeviceIoControl(
//			g_hDev, listDriver2, 
//			&i, sizeof(DWORD), 
//			&driverInfo, sizeof(DRIVERINFO), 
//			&size, NULL);
//
//		CString size;
//		size.Format(_TEXT("%06X"), driverInfo.size);
//		MessageBox(size);
//
//		//m_list.InsertItem(index, _TEXT(""));
//		//m_list.SetItemText(index, 0, strtemp);
//
//		//index++;
//	}
//}

//void CDlgDriver::OnBnClickedButton2()
//{
//	// TODO: 在此添加控件通知处理程序代码
//
//	// 第一次,确定有多少个
//	DWORD size = 0;
//	DWORD count = 0;
//	DeviceIoControl(g_hDev, enumDriver1, NULL, 0, &count, sizeof(DWORD), &size, NULL);
//	// 第二次,获取所有数据
//	PDRIVERINFO pDriverInfo = new DRIVERINFO[count * sizeof(DRIVERINFO)]{0};// 申请堆空间,并初始化为0
//	DeviceIoControl(g_hDev, enumDriver2, NULL, 0, pDriverInfo, count * sizeof(DRIVERINFO), &size, NULL);
//	// 循环插入
//	DWORD index = 0;
//	for (DWORD i = 0; i < count - 1; i++)//count-1,0环 do-while 多加一个
//	{
//		CString tmp;
//		// 插入行
//		m_list.InsertItem(index, _TEXT(""));
//		// 插入数据
//		tmp.Format(_TEXT("%08X"), pDriverInfo->base);
//		m_list.SetItemText(index, 0, tmp);
//		tmp.Format(_TEXT("%06X"), pDriverInfo->size);
//		m_list.SetItemText(index, 1, tmp);
//		tmp.Format(_TEXT("%s"), pDriverInfo->name);
//		m_list.SetItemText(index, 2, tmp);
//		// 下一行 下一驱动
//		pDriverInfo++;
//		index++;
//	}
//}
