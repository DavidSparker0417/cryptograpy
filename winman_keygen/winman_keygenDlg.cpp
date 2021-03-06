
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

uint8_t sk_blob[1172] = {
	0x07, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x32, 0x00, 0x08, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x79, 0x76, 0x68, 0xBD, 0x8A, 0x74, 0xA9, 0x59, 0x87, 0x9E, 0x4E, 0xCE,
	0xFD, 0xA7, 0x1E, 0x40, 0xBF, 0x41, 0xE3, 0x87, 0x1F, 0xB0, 0x9D, 0xDB, 0x80, 0xC4, 0xBA, 0x34,
	0x58, 0x41, 0xAC, 0xD6, 0x2C, 0xD9, 0x0A, 0x00, 0xB4, 0x83, 0x5E, 0x83, 0x6A, 0x00, 0x6C, 0x70,
	0x28, 0x6F, 0x93, 0xF6, 0x93, 0xEB, 0x6F, 0x00, 0xA3, 0xC1, 0x0F, 0xCA, 0x8C, 0x20, 0x18, 0xCF,
	0xF4, 0x62, 0x59, 0x9C, 0xE0, 0x02, 0xAB, 0x7F, 0xB4, 0xA2, 0x33, 0x88, 0x63, 0x28, 0x93, 0x07,
	0x65, 0x73, 0x6D, 0xA1, 0x96, 0x81, 0x4D, 0x18, 0xC6, 0xFA, 0x68, 0x1B, 0x44, 0xE5, 0x38, 0x51,
	0x0C, 0xEE, 0x38, 0xB7, 0x20, 0x78, 0x1E, 0x1A, 0xD1, 0x9F, 0x21, 0x8D, 0xB1, 0xEA, 0xB2, 0x7D,
	0xAD, 0x3C, 0x08, 0x23, 0x45, 0x89, 0x89, 0x29, 0x83, 0x69, 0xAD, 0xE4, 0x24, 0x84, 0x28, 0xAD,
	0x16, 0xDF, 0x5B, 0x99, 0xCC, 0x39, 0xFD, 0x51, 0xF3, 0xE4, 0xA1, 0x24, 0xE1, 0xB0, 0x7C, 0xFB,
	0x82, 0x36, 0x8B, 0x64, 0x2A, 0xE5, 0x64, 0xE3, 0x1F, 0x3A, 0x1F, 0xB2, 0x43, 0x33, 0x1D, 0xF2,
	0x84, 0x71, 0x83, 0xED, 0xF0, 0x5C, 0xBB, 0xF8, 0x6E, 0xF5, 0xB9, 0x51, 0x43, 0xA1, 0xC0, 0xCD,
	0xB2, 0x6D, 0x0F, 0xCD, 0x4C, 0x08, 0x92, 0xC7, 0xE3, 0xFA, 0x82, 0x1D, 0x90, 0x8D, 0x89, 0xBF,
	0x03, 0x4A, 0xED, 0xFE, 0x94, 0xE3, 0x64, 0x35, 0x4E, 0xA8, 0xCC, 0x44, 0x39, 0x98, 0xB4, 0x29,
	0x36, 0xA8, 0xED, 0x9A, 0x4C, 0x1B, 0x36, 0xBD, 0xB8, 0x6E, 0x73, 0x02, 0xFA, 0x50, 0xB4, 0x55,
	0x4F, 0x0D, 0x41, 0x04, 0xB1, 0xAF, 0xFD, 0xBD, 0x70, 0x0C, 0x1E, 0x13, 0x50, 0x47, 0x5C, 0x43,
	0x18, 0x85, 0xB0, 0xFF, 0x10, 0x40, 0xEF, 0x66, 0x62, 0x7B, 0xDD, 0x9D, 0x28, 0x1C, 0x63, 0xE5,
	0x43, 0x13, 0x0D, 0xF5, 0x2B, 0xD0, 0x0D, 0xD9, 0x78, 0x05, 0x86, 0xA5, 0x7E, 0xB7, 0x4C, 0xF7,
	0xB7, 0x12, 0x70, 0x5C, 0xCE, 0xB5, 0xF9, 0x32, 0xF5, 0xAF, 0xB0, 0x61, 0xF2, 0xA3, 0x76, 0xEF,
	0xB5, 0xBA, 0x5A, 0xC0, 0xA9, 0x23, 0x77, 0xBA, 0xBD, 0x0D, 0xE5, 0xE6, 0xA1, 0xD7, 0x74, 0x85,
	0xED, 0x3C, 0xB3, 0xB7, 0x32, 0xD6, 0x1D, 0x5F, 0x25, 0xC8, 0x5C, 0x0E, 0x84, 0xB3, 0xE5, 0x90,
	0xB7, 0x1C, 0x32, 0xCC, 0xB8, 0x44, 0xCA, 0xF3, 0xAB, 0x13, 0xC7, 0x31, 0xB1, 0x94, 0x03, 0x94,
	0xCF, 0xBA, 0xA9, 0x77, 0x3F, 0x24, 0x71, 0x2D, 0xAE, 0xC1, 0x69, 0x27, 0xB0, 0x2D, 0x70, 0x05,
	0x3E, 0x7B, 0x77, 0xB0, 0x16, 0x52, 0x1B, 0xB2, 0xFE, 0x46, 0x29, 0xB6, 0x89, 0x1F, 0x3E, 0x20,
	0x37, 0x93, 0x4F, 0xDD, 0x39, 0x44, 0x74, 0x41, 0xD2, 0x4B, 0x68, 0xC7, 0x30, 0xC0, 0x7B, 0xE8,
	0x53, 0x32, 0x21, 0xF7, 0xEB, 0x9D, 0x30, 0x77, 0xE9, 0x34, 0x9A, 0xC7, 0x23, 0xA0, 0xF5, 0x7C,
	0x52, 0x46, 0xF1, 0x1C, 0xD0, 0x2B, 0x5A, 0xED, 0x24, 0xFE, 0xE8, 0xD5, 0x7D, 0x25, 0x6D, 0x95,
	0x76, 0x42, 0xEC, 0xBE, 0xEA, 0xF1, 0x74, 0xD7, 0x1F, 0xBC, 0xA7, 0xBE, 0x13, 0x7D, 0x8E, 0xC5,
	0x02, 0x3D, 0xAC, 0x4F, 0x20, 0x5F, 0xD1, 0x4C, 0xB0, 0x09, 0x8C, 0xFA, 0x3C, 0xD3, 0xB9, 0xD6,
	0x40, 0x9D, 0xDB, 0xF4, 0x7B, 0xF8, 0x54, 0x5F, 0x75, 0x61, 0x7A, 0x57, 0x7F, 0xCC, 0x88, 0x18,
	0x5C, 0x16, 0xDD, 0xAE, 0x81, 0xFE, 0xC1, 0x2E, 0x75, 0xEF, 0x69, 0x42, 0xB0, 0x97, 0x72, 0xB1,
	0x28, 0xD9, 0x74, 0x47, 0xE6, 0xF3, 0xC6, 0x04, 0xD6, 0x4C, 0x61, 0x00, 0xCB, 0x0A, 0xFD, 0xB4,
	0x02, 0x57, 0x3C, 0x72, 0x91, 0x6D, 0xB9, 0x14, 0x95, 0x55, 0xFC, 0x58, 0xEE, 0x4B, 0xF9, 0x7E,
	0x6D, 0xC7, 0xD8, 0xFD, 0xFF, 0xCE, 0x3E, 0x1B, 0x14, 0x45, 0x0A, 0x19, 0x66, 0xEA, 0x1C, 0x68,
	0xF7, 0xED, 0x82, 0x23, 0x38, 0x0E, 0x8E, 0x3C, 0x04, 0xBB, 0x99, 0x37, 0x99, 0x95, 0xBB, 0x03,
	0xC1, 0x45, 0x73, 0xC7, 0x7A, 0xE1, 0xFA, 0xD9, 0x21, 0x3A, 0xEC, 0xFD, 0x40, 0xB5, 0x02, 0x22,
	0x32, 0xAB, 0x30, 0xCF, 0x84, 0xA5, 0xF6, 0x7A, 0x8F, 0x31, 0x49, 0x4A, 0x63, 0xB9, 0x21, 0xFE,
	0x0A, 0xF5, 0x4B, 0xE0, 0xA9, 0x8D, 0xCF, 0xD4, 0x18, 0xA9, 0x28, 0xEC, 0x9A, 0x60, 0x7E, 0x63,
	0xFD, 0x1F, 0xE4, 0x84, 0xA7, 0x76, 0x3D, 0x50, 0xB3, 0xBC, 0x7D, 0x67, 0xEB, 0xED, 0xCB, 0x5E,
	0x7A, 0x5E, 0xC1, 0xBF, 0x8F, 0xE9, 0x3A, 0xEA, 0xD1, 0xA7, 0x89, 0x57, 0xED, 0xFC, 0x93, 0xEF,
	0x19, 0x06, 0xE0, 0x84, 0xFF, 0xC9, 0xF6, 0x3F, 0x93, 0x3C, 0x50, 0xC4, 0x02, 0xEA, 0xE0, 0xE5,
	0xE5, 0xED, 0x2E, 0x02, 0xE3, 0x85, 0xBE, 0x03, 0x0F, 0x72, 0x9C, 0xC0, 0xDC, 0xD2, 0x3B, 0x8B,
	0xE4, 0xA1, 0x36, 0xFB, 0xD8, 0x92, 0xA4, 0xE6, 0xAE, 0xF1, 0xD8, 0xFC, 0x5F, 0xBB, 0xD9, 0x77,
	0xAB, 0x17, 0x04, 0x95, 0x50, 0x87, 0x0B, 0x64, 0x12, 0xE8, 0x25, 0x2D, 0xA6, 0x32, 0x93, 0xD6,
	0xD6, 0xF4, 0x3D, 0xEF, 0xC9, 0x57, 0x67, 0xEE, 0xB4, 0x28, 0x96, 0x02, 0xA8, 0x89, 0x75, 0x93,
	0x84, 0xE5, 0x02, 0x55, 0x79, 0xCA, 0x18, 0x3A, 0x83, 0xE2, 0xC4, 0xE1, 0xF4, 0x77, 0x42, 0xD3,
	0x01, 0x10, 0x5F, 0x3F, 0x31, 0xA7, 0x03, 0x75, 0x9E, 0xC8, 0x9E, 0x50, 0xFF, 0xF7, 0x4B, 0x01,
	0x5D, 0x16, 0x4E, 0x7A, 0x3B, 0xCE, 0x25, 0x50, 0xC8, 0xF7, 0xD2, 0x0C, 0x26, 0x1F, 0xDC, 0x4A,
	0x66, 0xCB, 0x38, 0x0D, 0xF9, 0xCA, 0x3C, 0x4C, 0xC7, 0xE5, 0xF9, 0x89, 0x89, 0xB2, 0x65, 0x5B,
	0x78, 0x88, 0x9E, 0x6D, 0xFB, 0xB4, 0x83, 0xB3, 0x78, 0x62, 0x20, 0xFF, 0xC8, 0x29, 0xAF, 0x9C,
	0x57, 0x0C, 0x90, 0xD8, 0x0B, 0x5E, 0xC7, 0xBE, 0x6F, 0xB1, 0xC7, 0x99, 0x3D, 0xA3, 0x4E, 0x02,
	0x29, 0xA7, 0x1E, 0x44, 0xF8, 0x0A, 0x4A, 0x20, 0xC5, 0xE9, 0x75, 0x7A, 0xE1, 0xEB, 0x11, 0x52,
	0xB9, 0x3B, 0xB2, 0x94, 0x9B, 0x0E, 0xF3, 0x33, 0x7B, 0x28, 0x19, 0xD8, 0xC2, 0x99, 0x14, 0x8B,
	0x7C, 0xA4, 0x52, 0x5E, 0x54, 0x23, 0x04, 0x5A, 0x4C, 0x38, 0x1A, 0x18, 0xD9, 0x4F, 0xFA, 0x94,
	0x72, 0x92, 0x20, 0xAF, 0x5A, 0xD7, 0x63, 0x28, 0xDC, 0xB0, 0x34, 0xC5, 0x50, 0x7A, 0x42, 0xD2,
	0xD4, 0xA3, 0xA3, 0x02, 0x2E, 0x06, 0x33, 0x4D, 0xDE, 0x9A, 0x0A, 0x9A, 0xD8, 0xBE, 0xED, 0x73,
	0xE2, 0x91, 0x0F, 0x4E, 0x86, 0x7C, 0xD0, 0x4E, 0x96, 0xE3, 0xB6, 0xE8, 0x9E, 0xD9, 0x70, 0xAE,
	0x28, 0x8A, 0x02, 0xD2, 0xD1, 0x87, 0x98, 0xB7, 0x50, 0xFD, 0xBE, 0x6D, 0x48, 0xE1, 0x5A, 0x0C,
	0xE4, 0xDD, 0x61, 0x0D, 0xB5, 0x35, 0x9E, 0xC6, 0x20, 0x9E, 0x24, 0x14, 0x0C, 0xA8, 0xF7, 0x57,
	0xCA, 0x4D, 0x29, 0xA0, 0x67, 0x3C, 0x7B, 0x2B, 0xF3, 0x13, 0x77, 0x6C, 0x8D, 0x34, 0xF7, 0x1D,
	0xA9, 0x6E, 0xF4, 0x96, 0xD8, 0x8D, 0xC4, 0xBC, 0x22, 0xE9, 0x36, 0xE6, 0xD1, 0x80, 0x97, 0x69,
	0x5D, 0x4E, 0x40, 0x1F, 0x9E, 0xCE, 0xCB, 0x13, 0xDB, 0x0E, 0x37, 0x78, 0xBF, 0x7E, 0xC1, 0x2E,
	0xE8, 0x0D, 0x44, 0xF9, 0x78, 0x3E, 0x75, 0xFF, 0x7A, 0x67, 0x84, 0x17, 0x4E, 0xFA, 0x50, 0x83,
	0x22, 0xEB, 0xB1, 0x3B, 0x6B, 0x50, 0xDB, 0xC0, 0xFE, 0xAE, 0x6A, 0x68, 0xB8, 0x8E, 0xFC, 0x9C,
	0x40, 0xDF, 0x55, 0x16, 0x0F, 0xC4, 0xDB, 0xB7, 0x11, 0xDF, 0x78, 0xF8, 0x20, 0xFE, 0x29, 0x50,
	0x05, 0x36, 0xCB, 0x77, 0x48, 0x5B, 0x7C, 0x5C, 0xF3, 0x3D, 0x7E, 0x74, 0x95, 0x78, 0x82, 0xF8,
	0x59, 0x2D, 0x55, 0x8A, 0x61, 0x6E, 0x81, 0x13, 0x46, 0x5B, 0x79, 0xCF, 0x5E, 0xC6, 0x92, 0x6D,
	0x5C, 0x3B, 0xE1, 0xA8, 0x08, 0x00, 0xA4, 0xF0, 0xFC, 0xBC, 0x4D, 0xCB, 0x20, 0x05, 0x25, 0xAA,
	0x25, 0x1F, 0x54, 0xD8, 0x52, 0x34, 0x20, 0xDB, 0x00, 0x68, 0x47, 0xC9, 0x91, 0xE2, 0x50, 0x55,
	0x87, 0x14, 0xB6, 0xB5, 0xE3, 0x68, 0x76, 0x7F, 0x5F, 0x6A, 0xA9, 0x38, 0x76, 0x26, 0x1D, 0x0F,
	0x85, 0x8D, 0x00, 0xC8, 0x11, 0x90, 0x9A, 0xA2, 0x20, 0xFB, 0x26, 0x09, 0xC1, 0x7C, 0xC7, 0xE3,
	0x71, 0x01, 0x88, 0x58, 0x6B, 0xDD, 0x99, 0xBC, 0x42, 0x74, 0x23, 0x26, 0xA3, 0xFE, 0xA7, 0xA9,
	0x7E, 0x3D, 0x3B, 0xBD, 0xCB, 0xBB, 0xF5, 0x14, 0x72, 0xE2, 0x62, 0x02, 0xB8, 0x89, 0x4D, 0x65,
	0x38, 0xE2, 0x76, 0xED
};

uint8_t pk_blob[276] = {
	0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31, 0x00, 0x08, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x79, 0x76, 0x68, 0xBD, 0x8A, 0x74, 0xA9, 0x59, 0x87, 0x9E, 0x4E, 0xCE,
	0xFD, 0xA7, 0x1E, 0x40, 0xBF, 0x41, 0xE3, 0x87, 0x1F, 0xB0, 0x9D, 0xDB, 0x80, 0xC4, 0xBA, 0x34,
	0x58, 0x41, 0xAC, 0xD6, 0x2C, 0xD9, 0x0A, 0x00, 0xB4, 0x83, 0x5E, 0x83, 0x6A, 0x00, 0x6C, 0x70,
	0x28, 0x6F, 0x93, 0xF6, 0x93, 0xEB, 0x6F, 0x00, 0xA3, 0xC1, 0x0F, 0xCA, 0x8C, 0x20, 0x18, 0xCF,
	0xF4, 0x62, 0x59, 0x9C, 0xE0, 0x02, 0xAB, 0x7F, 0xB4, 0xA2, 0x33, 0x88, 0x63, 0x28, 0x93, 0x07,
	0x65, 0x73, 0x6D, 0xA1, 0x96, 0x81, 0x4D, 0x18, 0xC6, 0xFA, 0x68, 0x1B, 0x44, 0xE5, 0x38, 0x51,
	0x0C, 0xEE, 0x38, 0xB7, 0x20, 0x78, 0x1E, 0x1A, 0xD1, 0x9F, 0x21, 0x8D, 0xB1, 0xEA, 0xB2, 0x7D,
	0xAD, 0x3C, 0x08, 0x23, 0x45, 0x89, 0x89, 0x29, 0x83, 0x69, 0xAD, 0xE4, 0x24, 0x84, 0x28, 0xAD,
	0x16, 0xDF, 0x5B, 0x99, 0xCC, 0x39, 0xFD, 0x51, 0xF3, 0xE4, 0xA1, 0x24, 0xE1, 0xB0, 0x7C, 0xFB,
	0x82, 0x36, 0x8B, 0x64, 0x2A, 0xE5, 0x64, 0xE3, 0x1F, 0x3A, 0x1F, 0xB2, 0x43, 0x33, 0x1D, 0xF2,
	0x84, 0x71, 0x83, 0xED, 0xF0, 0x5C, 0xBB, 0xF8, 0x6E, 0xF5, 0xB9, 0x51, 0x43, 0xA1, 0xC0, 0xCD,
	0xB2, 0x6D, 0x0F, 0xCD, 0x4C, 0x08, 0x92, 0xC7, 0xE3, 0xFA, 0x82, 0x1D, 0x90, 0x8D, 0x89, 0xBF,
	0x03, 0x4A, 0xED, 0xFE, 0x94, 0xE3, 0x64, 0x35, 0x4E, 0xA8, 0xCC, 0x44, 0x39, 0x98, 0xB4, 0x29,
	0x36, 0xA8, 0xED, 0x9A, 0x4C, 0x1B, 0x36, 0xBD, 0xB8, 0x6E, 0x73, 0x02, 0xFA, 0x50, 0xB4, 0x55,
	0x4F, 0x0D, 0x41, 0x04, 0xB1, 0xAF, 0xFD, 0xBD, 0x70, 0x0C, 0x1E, 0x13, 0x50, 0x47, 0x5C, 0x43,
	0x18, 0x85, 0xB0, 0xFF, 0x10, 0x40, 0xEF, 0x66, 0x62, 0x7B, 0xDD, 0x9D, 0x28, 0x1C, 0x63, 0xE5,
	0x43, 0x13, 0x0D, 0xF5
};

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
	
	//rsa2048_key_generate(&pubkey, &privkey);
	pubkey.blob = pk_blob;
	pubkey.blob_len = sizeof(pk_blob);

	privkey.blob = sk_blob;
	privkey.blob_len = sizeof(sk_blob);
	GetDlgItemText(EDT_DEVID, str);
	
	devinfo_len = wcstombs(dev_info, str.GetBuffer(), str.GetLength());

	activate_code = crypto_keygen(dev_info, devinfo_len, &privkey);
	str = CString(activate_code);
	SetDlgItemText(LBL_ACTIVATE_CODE, str);
	
	GetDlgItemText(LBL_ACTIVATE_CODE, str);
	len = wcstombs(active_code, str.GetBuffer(), str.GetLength());
	active_code[len] = 0;
	if (activation_checkout(active_code, dev_info, devinfo_len, &pubkey))
		AfxMessageBox(_T("Activation code validation success!"));
	else
		AfxMessageBox(_T("Activation code validation failed!"));
	SAFE_FREE(activate_code);
}
