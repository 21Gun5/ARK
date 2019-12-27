
// ARK_r3Dlg.cpp: 实现文件
//

#include "stdafx.h"
#include "ARK_r3.h"
#include "ARK_r3Dlg.h"
#include "afxdialogex.h"

#include "CDlgDriver.h"
#include "CDlgProcess.h"
#include "CDlgFile.h"
#include "CDlgRegTable.h"
#include "CDlgIDT.h"
#include "CDlgGDT.h"
#include "CDlgSSDT.h"
#include "Tools.h"
#include <process.h>



#ifdef _DEBUG
#define new DEBUG_NEW
#endif



// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CARKr3Dlg 对话框



CARKr3Dlg::CARKr3Dlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_ARK_R3_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CARKr3Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TAB1, m_tab);
	DDX_Control(pDX, IDC_TAB1, m_tab);
}

BEGIN_MESSAGE_MAP(CARKr3Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//ON_BN_CLICKED(IDC_BUTTON_DRIVER, &CARKr3Dlg::OnBnClickedButtonDriver)
	ON_NOTIFY(TCN_SELCHANGE, IDC_TAB1, &CARKr3Dlg::OnSelchangeTab1)
END_MESSAGE_MAP()


// CARKr3Dlg 消息处理程序

BOOL CARKr3Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	// 1 通过符号链接打开设备
	g_hDev = CreateFile(
		L"\\\\.\\deviceARK",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (g_hDev == INVALID_HANDLE_VALUE)
	{
		//printf("[3环程序]打开设备失败: %d\n", GetLastError());
		//system("pause");
		return 0;
	}
	//CloseHandle(hDev);

	// 2 初始化选项卡控件
	m_tab.InsertItem(0, L"驱动");
	m_tab.InsertItem(1, L"进程");
	m_tab.InsertItem(2, L"文件");
	m_tab.InsertItem(3, L"注册表");
	m_tab.InsertItem(4, L"IDT");
	m_tab.InsertItem(5, L"GDT");
	m_tab.InsertItem(6, L"SSDT");

	// 3 初始化三个选项卡对应的窗口
	// 新创建的窗口，父类指针[必须]为选项卡控件，如果不进行设置，那么
	// 窗口就无法响应到外部传入的消息
	m_tabWnd[0] = new CDlgDriver;
	m_tabWnd[0]->Create(IDD_DIALOG_DRIVER, &m_tab);
	m_tabWnd[1] = new CDlgProcess;
	m_tabWnd[1]->Create(IDD_DIALOG_PROCESS, &m_tab);
	m_tabWnd[2] = new CDlgFile;
	m_tabWnd[2]->Create(IDD_DIALOG_FILE, &m_tab);
	m_tabWnd[3] = new CDlgRegTable;
	m_tabWnd[3]->Create(IDD_DIALOG_REGTABLE, &m_tab);
	m_tabWnd[4] = new CDlgIDT;
	m_tabWnd[4]->Create(IDD_DIALOG_IDT, &m_tab);
	m_tabWnd[5] = new CDlgGDT;
	m_tabWnd[5]->Create(IDD_DIALOG_GDT, &m_tab);
	m_tabWnd[6] = new CDlgSSDT;
	m_tabWnd[6]->Create(IDD_DIALOG_SSDT, &m_tab);

	// 4 以选项卡为准，重新设置窗口的位置
	CRect Rect = { 0 };
	m_tab.GetClientRect(&Rect);
	Rect.DeflateRect(8, 33, 10, 10);
	for (int i = 0; i < 7; ++i)
		m_tabWnd[i]->MoveWindow(&Rect);

	// 5 默认显示第一个窗口
	ShowTabWnd(0);

	
	// 6 内核重载
	DWORD size = 0;
	DeviceIoControl(g_hDev, kernelReload, NULL, 0, NULL, 0, &size, NULL);
	// 7 安装HOOK
	DWORD curPid = (DWORD)_getpid();// 获取当前进程ID
	DeviceIoControl(g_hDev, hookSysEnter, &curPid, sizeof(DWORD), NULL, 0, &size, NULL);


	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CARKr3Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CARKr3Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CARKr3Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



// 显示选项卡内的指定项
void CARKr3Dlg::ShowTabWnd(int index)
{
	for (int i = 0; i < 7; ++i)
	{
		m_tabWnd[i]->ShowWindow(i == index ? SW_SHOWNORMAL : SW_HIDE);
	}
}

void CARKr3Dlg::OnSelchangeTab1(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
	ShowTabWnd(m_tab.GetCurSel());
}
