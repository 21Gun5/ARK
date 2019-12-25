#pragma once


// CDlgGDT 对话框

class CDlgGDT : public CDialogEx
{
	DECLARE_DYNAMIC(CDlgGDT)

public:
	CDlgGDT(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CDlgGDT();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_GDT };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_list;
	virtual BOOL OnInitDialog();
};
