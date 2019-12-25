#pragma once


// CDlgIDT 对话框

class CDlgIDT : public CDialogEx
{
	DECLARE_DYNAMIC(CDlgIDT)

public:
	CDlgIDT(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CDlgIDT();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_IDT };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_list;
	virtual BOOL OnInitDialog();
};
