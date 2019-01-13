/***************************************************************************
                          getpassword.h  -  description
                             -------------------
    begin                : Tue Aug 5 2003
    copyright            : (C) 2003 by ARRL
    author               : Jon Bloom
    email                : jbloom@arrl.org
    revision             : $Id: getpassword.h,v 1.3 2003/08/11 14:20:13 jbloom Exp $
 ***************************************************************************/

#ifndef __getpassword_h
#define __getpassword_h

#ifdef HAVE_CONFIG_H
#include "sysconfig.h"
#endif

#include "wx/wxprec.h"

#ifdef __BORLANDC__
	#pragma hdrstop
#endif

#ifndef WX_PRECOMP
	#include "wx/wx.h"
#endif

#include "wx/wxhtml.h"

class GetPasswordDialog : public wxDialog {
public:
	GetPasswordDialog(wxWindow *parent, const wxString& title = "Enter password",
		const wxString& message = "Enter password",
		wxHtmlHelpController *help = 0, wxString helpfile = "");
	wxString Password() { return _password; }
	virtual bool TransferDataFromWindow();
private:
	void OnOk(wxCommandEvent&);
	void OnCancel(wxCommandEvent&);
	void OnHelp(wxCommandEvent&);

	wxHtmlHelpController *_help;
	wxString _helpfile;
	wxString _password;
	wxTextCtrl *_pw;	
	DECLARE_EVENT_TABLE()
};

class GetNewPasswordDialog : public wxDialog {
public:
	GetNewPasswordDialog(wxWindow *parent, const wxString& title = "New password",
		const wxString& message = "Enter new password", bool blankok = false,
		wxHtmlHelpController *help = 0, wxString helpfile = "");
	wxString Password() { return _password; }
private:
	void PWChange(wxCommandEvent&);
	void OnOk(wxCommandEvent&);
	void OnCancel(wxCommandEvent&);
	void OnHelp(wxCommandEvent&);

	bool _blankok;
	wxHtmlHelpController *_help;
	wxString _helpfile;
	wxString _password;
	wxTextCtrl *_pw1, *_pw2;
	wxButton *_okbut;
	wxStaticText *_pwstatus;
	DECLARE_EVENT_TABLE()
};

#endif	// __getpassword_h
