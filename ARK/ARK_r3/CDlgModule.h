#pragma once


// CDlgModule 对话框

class CDlgModule : public CDialogEx
{
	DECLARE_DYNAMIC(CDlgModule)

public:
	CDlgModule(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CDlgModule();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_MODULE };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_list;
	DWORD m_curProcIndex;
	void SetCurProcessIndex(DWORD index);
	virtual BOOL OnInitDialog();
};
