/***************************************************************************
                          loadcertwiz.h  -  description
                             -------------------
    begin                : Wed Aug 6 2003
    copyright            : (C) 2003 by ARRL
    author               : Jon Bloom
    email                : jbloom@arrl.org
    revision             : $Id: loadcertwiz.h,v 1.4 2003/08/11 14:20:13 jbloom Exp $
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "sysconfig.h"
#endif

#ifndef __loadcertwiz_h
#define __loadcertwiz_h

#include "extwizard.h"

class LCW_Page;
class notifyData;

class LoadCertWiz : public ExtWizard {
public:
	LoadCertWiz(wxWindow *parent, wxHtmlHelpController *help = 0, const wxString& title = wxEmptyString);
	~LoadCertWiz();
	LCW_Page *GetCurrentPage() { return (LCW_Page *)wxWizard::GetCurrentPage(); }
	bool RunWizard();
	void ResetNotifyData();
	notifyData *GetNotifyData() { return _nd; }
private:
	LCW_Page *_first;
	class notifyData *_nd;
};

class LCW_Page : public ExtWizard_Page {
public:
	LCW_Page(LoadCertWiz *parent) : ExtWizard_Page(parent) {}
	LoadCertWiz *Parent() { return (LoadCertWiz *)_parent; }
};

class LCW_IntroPage : public LCW_Page {
public:
	LCW_IntroPage(LoadCertWiz *parent, LCW_Page *tq6next);
	virtual bool TransferDataFromWindow();
	void SetNextPages(LCW_Page *p12, LCW_Page *tq6);
private:
	wxRadioButton *_p12but;
	LCW_Page *_tq6next;
};

class LCW_P12PasswordPage : public LCW_Page {
public:
	LCW_P12PasswordPage(LoadCertWiz *parent);
	virtual bool TransferDataFromWindow();
	wxString GetPassword() const;
	void SetFilename(const wxString& filename) { _filename = filename; }
private:
	wxTextCtrl *_pwin;
	wxString _filename;
	wxStaticText *tc_status;
};

class LCW_FinalPage : public LCW_Page {
public:
	LCW_FinalPage(LoadCertWiz *parent);
	virtual void refresh();
private:
	wxStaticText *tc_status;
};

class notifyData {
public:
	struct counts {
		int loaded, error, duplicate;
	};
	struct counts root, ca, user, pkey, config;
	notifyData() {
		root.loaded = root.error = root.duplicate = 0;
		ca.loaded = ca.error = ca.duplicate = 0;
		user.loaded = user.error = user.duplicate = 0;
		pkey.loaded = pkey.error = pkey.duplicate = 0;
		config.loaded = config.error = config.duplicate = 0;
	}
	wxString Message() const;
};

inline bool
LoadCertWiz::RunWizard() {
	return wxWizard::RunWizard(_first);
}

inline void
LoadCertWiz::ResetNotifyData() {
	if (_nd)
		delete _nd;
	_nd = new notifyData;
}

inline
LoadCertWiz::~LoadCertWiz() {
	if (_nd)
		delete _nd;
}

int notifyImport(int type, const char *message, void *);


#endif	// __loadcertwiz_h

