/***************************************************************************
                          crqwiz.h  -  description
                             -------------------
    begin                : Sat Jun 15 2002
    copyright            : (C) 2002 by ARRL
    author               : Jon Bloom
    email                : jbloom@arrl.org
    revision             : $Id$
 ***************************************************************************/

#ifndef __crqwiz_h
#define __crqwiz_h

#ifdef HAVE_CONFIG_H
#include "sysconfig.h"
#endif

#include <wx/wxprec.h>

#ifdef __BORLANDC__
	#pragma hdrstop
#endif

#ifndef WX_PRECOMP
	#include <wx/wx.h>
#endif

#include <wx/radiobox.h>

#include <wx/wxhtml.h>
#include <wx/combobox.h>

#include <vector>
#include <map>

#include "extwizard.h"
#include "certtree.h"

#ifndef ADIF_BOOLEAN
	#define ADIF_BOOLEAN // Hack!
#endif
#include "tqsllib.h"

using std::vector;

class CRQ_Page;
class CRQ_NamePage;

enum {
	CRQ_NOT_SIGNED = 0,		// Not signing at all
	CRQ_SIGN_MAYBE = 1,		// Not forcing signature
	CRQ_SIGN_PORTABLE = 2,		// Portable call, must sign
	CRQ_SIGN_REPLACEMENT = 3,	// Replacement or former call
	CRQ_SIGN_QSL_MGR = 4,		// QSL manager, Club, DXpedition
	CRQ_SIGN_1X1 = 5,		// US 1x1
	CRQ_SIGN_SPC_EVENT = 6,		// Special event
	CRQ_SIGN_NONE = 7,		// Entity NONE
	CRQ_SIGN_RENEWAL = 8		// Renewing
};

typedef std::map <int, wxString> prefixMap;

class CRQWiz : public ExtWizard {
 public:
	CRQWiz(TQSL_CERT_REQ *crq, 	tQSL_Cert cert, wxWindow* parent, wxHtmlHelpController *help = 0,
		const wxString& title = _("Request a new Callsign Certificate"));
	~CRQWiz();
	CRQ_Page *GetCurrentPage() { return reinterpret_cast<CRQ_Page *>(wxWizard::GetCurrentPage()); }
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Woverloaded-virtual"
#endif
	bool RunWizard();
#ifdef __clang__
#pragma clang diagnostic pop
#endif
	bool ShouldBeSigned(void);	// Should this be signed?
	bool MustBeSigned(void);	// Should this be signed?
	void initPrefixes(void);// Load prefix map
	bool validcerts;	// True if there are valid certificates
	int nprov;		// Number of providers
	int signIt;		// Should this be signed? Why?
	bool CertPwd;		// Should we prompt for a password?
	wxCoord maxWidth;	// Width of longest string
	tQSL_Cert _cert;
	bool renewal;		// True if this is a renewal
	// ProviderPage data
	CRQ_Page *providerPage;
	TQSL_PROVIDER provider;
	// CallsignPage data
	CRQ_Page *callsignPage;
	wxString callsign;
	wxString home_call;
	wxString modifier;
	tQSL_Date qsonotbefore, qsonotafter;
	bool usa;		// Set true when a US entity
	bool validusa;		// Set true when currently valid
	int dxcc;
	bool onebyone;		// US 1x1 callsign
	// NamePage data
	CRQ_NamePage *namePage;
	wxString name, addr1, addr2, city, state, zip, country;
	// EmailPage data
	CRQ_Page *emailPage;
	wxString email;
	tQSL_Cert *qcertlist;
	int nqcert;
	// PasswordPage data
	CRQ_Page *pwPage;
	wxString password;
	// TypePage data
	CRQ_Page *typePage;
	int certType;
	// SignPage data
	CRQ_Page *signPage;
	tQSL_Cert cert;
	TQSL_CERT_REQ *_crq;
	bool portable;		// Portable call
	int forceSigning;	// Whether or not to force signing
	bool replacementCall;	// Replacement for existing callsign. Require signing
	bool networkError;	// Got a network error - timeout, etc.
	bool goodULSData;	// Got ULS info and it's complete
	bool expired;		// Set true if the request has an end-date in the past

	prefixMap prefixRegex;
	prefixMap entityNames;
	void insertRegex(int ent, wxString& reg) { prefixRegex[ent] = reg;}
	void insertName(int ent, wxString& name) { entityNames[ent] = name;}
	wxString getEntityName(int ent) { return entityNames[ent]; }
	wxString getEntityRegex(int ent) { return prefixRegex[ent]; }
	int getNumRegex(void) { return prefixRegex.size(); }
	int getNumNames(void) { return entityNames.size(); }
	bool skipFile;

 private:
	CRQ_Page *_first;
	static void startElement(void *userData, const char *name, const char **atts);
	long pmajor, pminor;
};

class CRQ_Page : public ExtWizard_Page {
 public:
	explicit CRQ_Page(CRQWiz* parent = NULL) : ExtWizard_Page(parent) {valMsg = wxT("");}
	CRQWiz *Parent() { return reinterpret_cast<CRQWiz *>(_parent); }
	wxString valMsg;
};

class CRQ_ProviderPage : public CRQ_Page {
 public:
	explicit CRQ_ProviderPage(CRQWiz *parent, TQSL_CERT_REQ *crq = 0);
	virtual bool TransferDataFromWindow();
 private:
	void DoUpdateInfo();
	void UpdateInfo(wxCommandEvent&);
	vector<TQSL_PROVIDER> providers;
	tqslComboBox *tc_provider;
	wxStaticText *tc_provider_info;

	DECLARE_EVENT_TABLE()
};

class CRQ_CallsignPage : public CRQ_Page {
 public:
	explicit CRQ_CallsignPage(CRQWiz *parent, TQSL_CERT_REQ *crq = 0);
	virtual bool TransferDataFromWindow();
	virtual const char *validate();
	virtual CRQ_Page *GetPrev() const;
	virtual CRQ_Page *GetNext() const;
	void OnShowHide(wxCommandEvent&) { ShowHide(); }
	void ShowHide();
	bool validPrefix(const std::string& prefix);
	wxCheckBox *tc_showall;
	bool showAll;			// Set true to show all
 private:
	wxTextCtrl *tc_call;
	tqslComboBox *tc_qsobeginy, *tc_qsobeginm, *tc_qsobegind, *tc_dxcc;;
	tqslComboBox *tc_qsoendy, *tc_qsoendm, *tc_qsoendd;
	wxStaticText *tc_cs_status;
	bool initialized;		// Set true when validating makes sense
	CRQWiz *_parent;
	DECLARE_EVENT_TABLE()
};

class CRQ_NamePage : public CRQ_Page {
 public:
	explicit CRQ_NamePage(CRQWiz *parent, TQSL_CERT_REQ *crq = 0);
	virtual bool TransferDataFromWindow();
	virtual const char *validate();
	virtual CRQ_Page *GetPrev() const;
	virtual CRQ_Page *GetNext() const;
	void Preset(CRQ_CallsignPage *ip);
	void setName(wxString &s) { tc_name->SetValue(s);}
	void setAddr1(wxString &s) { tc_addr1->SetValue(s);}
	void setAddr2(wxString &s) { tc_addr2->SetValue(s);}
	void setCity(wxString &s) { tc_city->SetValue(s);}
	void setState(wxString &s) { tc_state->SetValue(s);}
	void setZip(wxString &s) { tc_zip->SetValue(s);}
	void setCountry(wxString &s) { tc_country->SetValue(s);}
 private:
	wxTextCtrl *tc_name, *tc_addr1, *tc_addr2, *tc_city, *tc_state,
		*tc_zip, *tc_country;
	wxStaticText *tc_addr_status;
	bool initialized;
	CRQWiz *_parent;

	DECLARE_EVENT_TABLE()
};

class CRQ_EmailPage : public CRQ_Page {
 public:
	explicit CRQ_EmailPage(CRQWiz *parent, TQSL_CERT_REQ *crq = 0);
	virtual bool TransferDataFromWindow();
	virtual const char *validate();
	virtual CRQ_Page *GetPrev() const;
	virtual CRQ_Page *GetNext() const;
 private:
	CRQWiz *_parent;
	wxTextCtrl *tc_email;
	wxStaticText *tc_em_status;
	bool initialized;

	DECLARE_EVENT_TABLE()
};

class CRQ_PasswordPage : public CRQ_Page {
 public:
	explicit CRQ_PasswordPage(CRQWiz *parent);
	virtual bool TransferDataFromWindow();
	virtual const char *validate();
	virtual CRQ_Page *GetPrev() const;
	virtual CRQ_Page *GetNext() const;
 private:
	wxTextCtrl *tc_pw1, *tc_pw2;
	wxStaticText *tc_pwd_status;
	bool initialized;
	CRQWiz *_parent;
	wxStaticText *fwdPrompt;
	int em_w;
	int em_h;

	DECLARE_EVENT_TABLE()
};

class CRQ_TypePage : public CRQ_Page {
 public:
	explicit CRQ_TypePage(CRQWiz *parent);
	virtual bool TransferDataFromWindow();
	virtual CRQ_Page *GetPrev() const;
	virtual CRQ_Page *GetNext() const;
	// TypePage data
 private:
	bool initialized;
	wxRadioBox *certType;
	CRQWiz *_parent;

	DECLARE_EVENT_TABLE()
};

class CRQ_SignPage : public CRQ_Page {
 public:
	explicit CRQ_SignPage(CRQWiz *parent, TQSL_CERT_REQ *crq = 0);
	virtual bool TransferDataFromWindow();
	void CertSelChanged(wxTreeEvent&);
	virtual const char *validate();
	virtual void refresh();
	virtual CRQ_Page *GetPrev() const;
 private:
	CertTree *cert_tree;
	wxStaticText *tc_sign_status;
	bool initialized;
	int em_w;
	int em_h;
	void OnPageChanging(wxWizardEvent &);
	CRQWiz *_parent;
	wxStaticText* introText;
	wxString introContent;
	DECLARE_EVENT_TABLE()
};

inline bool
CRQWiz::RunWizard() {
	return wxWizard::RunWizard(_first);
}

struct prefixlist {
	int entity;
	const char *regex;
};

#endif // __crqwiz_h
