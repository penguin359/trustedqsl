/***************************************************************************
                          extwizard.h  -  description
                             -------------------
    begin                : Thu Aug 7 2003
    copyright            : (C) 2003 by ARRL
    author               : Jon Bloom
    email                : jbloom@arrl.org
    revision             : $Id: extwizard.h,v 1.3 2003/08/14 18:32:02 jbloom Exp $
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "sysconfig.h"
#endif

#ifndef __extwizard_h
#define __extwizard_h

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

#include "wx/wizard.h"
#include "wx/wxhtml.h"

class ExtWizard_Page;

class ExtWizard : public wxWizard {
public:
	ExtWizard(wxWindow *parent, wxHtmlHelpController *help = 0, const wxString& title = wxEmptyString);
	ExtWizard_Page *GetCurrentPage() { return (ExtWizard_Page *)wxWizard::GetCurrentPage(); }
	wxHtmlHelpController *GetHelp() { return _help; }
	void DisplayHelp(const wxString& file) { if (_help) _help->Display(file); }
	void ReportSize(const wxSize& size);
	void AdjustSize() { SetPageSize(_minsize); }
	bool HaveHelp() const { return _help != 0; }
protected:
	void OnPageChanged(wxWizardEvent&);
	wxHtmlHelpController *_help;
	wxSize _minsize;

	DECLARE_EVENT_TABLE()
};

class ExtWizard_Page : public wxWizardPageSimple {
public:
	ExtWizard_Page(ExtWizard *parent) : wxWizardPageSimple(parent), _parent(parent), _helpfile("") {}

	virtual const char *validate() { return NULL; }	// Returns error message string or NULL=no error
	virtual void refresh() { }	// Updates page contents based on page-specific criteria
	void check_valid(wxEvent&);
protected:
	ExtWizard *_parent;
	void AdjustPage(wxBoxSizer *sizer, const wxString& helpfile = "");
private:
	void OnHelp(wxCommandEvent&) { if (_helpfile != "") _parent->DisplayHelp(_helpfile); }
	wxString _helpfile;

	DECLARE_EVENT_TABLE();
};

#endif	// __extwizard_h
