
// winman_keygenDlg.cpp : implementation file
//

#include "stdafx.h"
#include "winman_keygen.h"
#include "winman_keygenDlg.h"
#include "afxdialogex.h"

#include "crypto.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// Cwinman_keygenDlg dialog



Cwinman_keygenDlg::Cwinman_keygenDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(Cwinman_keygenDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void Cwinman_keygenDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(Cwinman_keygenDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &Cwinman_keygenDlg::OnBnClickedOk)
	ON_BN_CLICKED(BTN_GENERATE, &Cwinman_keygenDlg::OnBnClickedGenerate)
END_MESSAGE_MAP()


// Cwinman_keygenDlg message handlers

BOOL Cwinman_keygenDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	CEdit* actEditCtrl = (CEdit*)GetDlgItem(LBL_ACTIVATE_CODE);
	actEditCtrl->ModifyStyle(ES_AUTOHSCROLL, 0);
	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void Cwinman_keygenDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR Cwinman_keygenDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void Cwinman_keygenDlg::OnBnClickedOk()
{
	// TODO: Add your control notification handler code here
	CDialogEx::OnOK();
}


void Cwinman_keygenDlg::OnBnClickedGenerate()
{
	// TODO: Add your control notification handler code here
	RSA2048_KEY_BLOB pubkey = { 0 }, privkey = { 0 };
	CString str;
	char* activate_code = NULL;
	char dev_info[1024];
	char active_code[1024];
	size_t devinfo_len = 0;
	size_t len;
	
	rsa2048_key_generate(&pubkey, &privkey);
	GetDlgItemText(EDT_DEVID, str);
	
	devinfo_len = wcstombs(dev_info, str.GetBuffer(), str.GetLength());

	activate_code = crypto_keygen(dev_info, devinfo_len, &privkey);
	str = CString(activate_code);
	SetDlgItemText(LBL_ACTIVATE_CODE, str);
	
	GetDlgItemText(LBL_ACTIVATE_CODE, str);
	len = wcstombs(active_code, str.GetBuffer(), str.GetLength());
	active_code[len] = 0;
	if (activation_checkout(active_code, dev_info, devinfo_len, &privkey))
		AfxMessageBox(_T("Activation code validation sucess!"));
	else
		AfxMessageBox(_T("Activation code validation failed!"));
	SAFE_FREE(pubkey.blob);
	SAFE_FREE(privkey.blob);
	SAFE_FREE(activate_code);
}
