#pragma once


// CDlgDriver 对话框

class CDlgDriver : public CDialogEx
{
	DECLARE_DYNAMIC(CDlgDriver)

public:
	CDlgDriver(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CDlgDriver();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_DRIVER };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_list;
	virtual BOOL OnInitDialog();
	//afx_msg void OnBnClickedButton2();
};
