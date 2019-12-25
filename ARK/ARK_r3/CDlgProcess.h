#pragma once


// CDlgProcess 对话框

class CDlgProcess : public CDialogEx
{
	DECLARE_DYNAMIC(CDlgProcess)

public:
	CDlgProcess(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CDlgProcess();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_PROCESS };
#endif

protected:

	CMenu m_menu;

	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
//	afx_msg void OnBnClickedButton1();
	CListCtrl m_list;
	afx_msg void OnKillprocess();
	afx_msg void OnHideprocess();
	afx_msg void OnEnumthread();
	afx_msg void OnEnummodu();
	afx_msg void OnRclickList1(NMHDR *pNMHDR, LRESULT *pResult);
//	afx_msg void OnBnClickedButtonRenew();
	afx_msg void OnRenew();
};
