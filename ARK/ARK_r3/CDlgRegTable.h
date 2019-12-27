#pragma once


// CDlgRegTable 对话框

class CDlgRegTable : public CDialogEx
{
	DECLARE_DYNAMIC(CDlgRegTable)

public:
	CDlgRegTable(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CDlgRegTable();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_REGTABLE };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
};
