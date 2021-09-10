
// winman_keygen.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// Cwinman_keygenApp:
// See winman_keygen.cpp for the implementation of this class
//

class Cwinman_keygenApp : public CWinApp
{
public:
	Cwinman_keygenApp();

// Overrides
public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern Cwinman_keygenApp theApp;