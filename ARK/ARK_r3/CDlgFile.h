#pragma once


// CDlgFile 对话框

class CDlgFile : public CDialogEx
{
	DECLARE_DYNAMIC(CDlgFile)

public:
	CDlgFile(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CDlgFile();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_FILE };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
};
