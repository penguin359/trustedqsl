/***************************************************************************
                          crqwiz.cpp  -  description
                             -------------------
    begin                : Sat Jun 15 2002
    copyright            : (C) 2002 by ARRL
    author               : Jon Bloom
    email                : jbloom@arrl.org
    revision             : $Id$
 ***************************************************************************/

#include "crqwiz.h"
#include <ctype.h>
#include <stdlib.h>
#include <wx/validate.h>
#include <wx/datetime.h>
#include <wx/config.h>
#include <wx/tokenzr.h>
#include <wx/regex.h>
#include <algorithm>
#include <iostream>
#ifdef DEBUG
#include <fstream>
#endif
#include <string>
#include <vector>
#include <map>
#include "dxcc.h"
#include "util.h"
#include "tqslctrls.h"
#include "tqsltrace.h"
#include "tqsl_prefs.h"

#include "winstrdefs.h"

extern int SaveAddressInfo(const char *callsign, int dxcc);

extern int GetULSInfo(const char *callsign, wxString &name, wxString &attn, wxString &street, wxString &city, wxString &state, wxString &zip);

using std::string;
using std::make_pair;

extern int get_address_field(const char *callsign, const char *field, string& result);

static wxString callTypeChoices[] = {
         _("This callsign replaces my existing callsign"),
	 _("This is my former callsign"),
         _("I am the QSL manager for this callsign"),
	 _("This is a club callsign"),
	 _("This is a DXpedition callsign"),
	 _("This is a special event callsign"),
         _("None of these apply")
};

// List of DXCC entities in the US.
static int USEntities[] = { 6,  // Alaska
			    9,  // American Samoa
			   20,  // Baker and Howland
			   43,  // Desecheo Island
			  103,  // Guam
			  105,  // Guantanamo Bay
			  110,  // Hawaii
			  123,  // Johnston Island
			  138,  // Kure Island
			  166,  // Mariana Islands
			  174,  // Midway Island
			  182,  // Navassa Island
			  197,  // Palmyra & Jarvis
			  202,  // Puerto Rico
			  285,  // US Virgin Islands
			  291,  // USA
			  297,  // Wake Island
			  515,  // Swains Island
			   -1 };

typedef map <int, wxString> prefixMap;
static prefixMap prefixRegex;
static prefixMap entityNames;

static void
initPrefixes() {
	if (prefixRegex.size() > 0)
		return;
	char prefixfile[TQSL_MAX_PATH_LEN];
	FILE *lfp;
#ifdef _WIN32
	snprintf(prefixfile, sizeof prefixfile, "%s\\prefixes.dat", tQSL_RsrcDir);
	wchar_t *wfilename = utf8_to_wchar(prefixfile);
	if ((lfp = _wfopen(wfilename, L"rb, ccs=UTF-8")) == NULL) {
		free_wchar(wfilename);
		return;
	}
#else
	snprintf(prefixfile, sizeof prefixfile, "%s/prefixes.dat", tQSL_RsrcDir);
	if ((lfp = fopen(prefixfile, "rb")) == NULL) {
		return;
	}
#endif
	char pBuf[1024];
	while (fgets(pBuf, sizeof pBuf, lfp)) {
		if (pBuf[0] == '/' && pBuf[1] == '/')			// Comments
			continue;
		wxStringTokenizer pData(wxString::FromUTF8(pBuf), wxT(","));
		int entnum = strtol(pData.GetNextToken().ToUTF8(), NULL, 10);
		if (entnum == 0)					// Entity is first char
			continue;
		prefixRegex[entnum] = pData.GetNextToken();		// Then regex
		wxString eName = pData.GetNextToken();
		while (pData.CountTokens() > 0) {
			eName = eName + pData.GetLastDelimiter();
			eName = eName + pData.GetNextToken();
		}
		eName = eName.Trim();			// Last is entity name

		// Translate "(Deleted)" to local language
		wxString del = wxGetTranslation(wxT("DELETED"));
		if (del != wxT("DELETED"))
			eName.Replace(wxT("Deleted"), wxGetTranslation(wxT("DELETED")));
		entityNames[entnum] = eName;
	}
	fclose(lfp);
}

static bool
isUSCallsign(wxString& call) {
	wxString first = call.Upper().Left(1);
	wxString second = call.Upper().Left(2);

	if (call.size() < 3) {
		return false;
	}
	if (call.Find(wxT("/")) != wxNOT_FOUND) {
		return false;
	}
	if (first == wxT("W") || first == wxT("K") || first == wxT("N") ||
	    (second >= wxT("AA") && second <= wxT("AL"))) {
		return true;
	}
	return false;
}

static bool
isUSEntity(int entity) {
	for (int i = 0; USEntities[i] > 0; i++) {
		if (entity == USEntities[i]) {
			return true;
		}
	}
	return false;
}

CRQWiz::CRQWiz(TQSL_CERT_REQ *crq, tQSL_Cert xcert, wxWindow *parent, wxHtmlHelpController *help,
	const wxString& title)
	: ExtWizard(parent, help, title), cert(xcert), _crq(crq)  {
	tqslTrace("CRQWiz::CRQWiz", "crq=%lx, xcert=%lx, title=%s", reinterpret_cast<void *>(cert), reinterpret_cast<void *>(xcert), S(title));

	dxcc = -1;
	validcerts = false;		// No signing certs to use
	onebyone = false;
	signIt = CRQ_SIGN_MAYBE;	// Not forcing signing of this
	portable = false;		// Not portable
	replacementCall = false;	// Not a replacement
	renewal = (_crq != NULL);	// It's a renewal if there's a CRQ provided
	usa = validusa = false;		// Not usa
	expired = false;

	initPrefixes();			// Initialize prefix regex list

	// Get count of valid certificates
	int ncerts = 0;
	if (!tqsl_selectCertificates(NULL, &ncerts, NULL, 0, NULL, NULL, 0)) {
		validcerts = (ncerts > 0);
	}
	nprov = 1;
	networkError = false;
	if (tqsl_getNumProviders(&nprov))
		nprov = 0;
	providerPage = new CRQ_ProviderPage(this, _crq);
	signPage = new CRQ_SignPage(this, _crq);
	callsignPage = new CRQ_CallsignPage(this, _crq);
	namePage = new CRQ_NamePage(this, _crq);
	emailPage = new CRQ_EmailPage(this, _crq);
	wxConfig *config = reinterpret_cast<wxConfig *>(wxConfig::Get());
	config->Read(wxT("CertPwd"), &CertPwd, DEFAULT_CERTPWD);
	pwPage = new CRQ_PasswordPage(this);
	typePage = new CRQ_TypePage(this);
	if (nprov != 1)
		wxWizardPageSimple::Chain(providerPage, callsignPage);
	wxWizardPageSimple::Chain(callsignPage, typePage);
	wxWizardPageSimple::Chain(typePage, namePage);
	wxWizardPageSimple::Chain(namePage, emailPage);
	wxWizardPageSimple::Chain(emailPage, pwPage);
	if (!cert)
		wxWizardPageSimple::Chain(pwPage, signPage);
	if (nprov == 1)
		_first = callsignPage;
	else
		_first = providerPage;
	AdjustSize();
	CenterOnParent();
}

bool
CRQWiz::ShouldBeSigned(void) {
	switch (signIt) {
		case CRQ_NOT_SIGNED:		// Don't sign if no certs
		case CRQ_SIGN_RENEWAL:		// or a renewal
			return false;
		case CRQ_SIGN_PORTABLE:		// Portable must be signed
		case CRQ_SIGN_REPLACEMENT:	// Replacement signed by current
		case CRQ_SIGN_1X1:		// 1x1 must be signed
		case CRQ_SIGN_QSL_MGR:		// QSL Mgr - Maybe
		case CRQ_SIGN_SPC_EVENT:	// Special event - Maybe
		case CRQ_SIGN_NONE:		// NONE - always signed
		case CRQ_SIGN_MAYBE:		// Dunno. Maybe.
		default:
			return true;
	}
}

bool
CRQWiz::MustBeSigned(void) {
	switch (signIt) {
		case CRQ_NOT_SIGNED:		// Don't sign if no certs
		case CRQ_SIGN_RENEWAL:		// or a renewal
		case CRQ_SIGN_MAYBE:		// Dunno. Maybe.
		case CRQ_SIGN_SPC_EVENT:	// Special event - Maybe
		case CRQ_SIGN_QSL_MGR:		// QSL Mgr - Maybe
			return false;
		case CRQ_SIGN_PORTABLE:		// Portable must be signed
		case CRQ_SIGN_REPLACEMENT:	// Replacement signed by current
		case CRQ_SIGN_1X1:		// 1x1 must be signed
		case CRQ_SIGN_NONE:		// NONE - always signed
		default:
			return true;
	}
}

// Page constructors

BEGIN_EVENT_TABLE(CRQ_ProviderPage, CRQ_Page)
	EVT_COMBOBOX(ID_CRQ_PROVIDER, CRQ_ProviderPage::UpdateInfo)
END_EVENT_TABLE()

static bool
prov_cmp(const TQSL_PROVIDER& p1, const TQSL_PROVIDER& p2) {
	return strcasecmp(p1.organizationName, p2.organizationName) < 0;
}

CRQ_ProviderPage::CRQ_ProviderPage(CRQWiz *parent, TQSL_CERT_REQ *crq) :  CRQ_Page(parent) {
	tqslTrace("CRQ_ProviderPage::CRQ_ProviderPage", "parent=%lx, crq=%lx", reinterpret_cast<void *>(parent), reinterpret_cast<void *>(crq));
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);

	wxWindowDC dc(this);
	dc.SetFont(this->GetFont());
	Parent()->maxWidth = 0;

	wxCoord em_w, em_h;
	dc.GetTextExtent(wxString(wxT("M")), &em_w, &em_h);

	if (Parent()->maxWidth < em_w * 40)
		Parent()->maxWidth = em_w * 40;

	wxString lbl = _("This will create a new Callsign Certificate request file.");
		lbl += wxT("\n\n");
		lbl += _("Once you supply the requested information and the request file has been created, you must send the request file to the certificate issuer.");
	wxStaticText *st = new wxStaticText(this, -1, lbl);
	st->SetSize(Parent()->maxWidth + em_w * 2, em_h * 5);
	st->Wrap(Parent()->maxWidth + em_w * 3);

	sizer->Add(st, 0, wxALL, 10);

	sizer->Add(new wxStaticText(this, -1, _("Certificate Issuer:")), 0, wxLEFT|wxRIGHT, 10);
	tc_provider = new tqslComboBox(this, ID_CRQ_PROVIDER, wxT(""), wxDefaultPosition,
		wxDefaultSize, 0, 0, wxCB_DROPDOWN|wxCB_READONLY);
	ACCESSIBLE(tc_provider, ComboBoxAx);
	tc_provider->SetName(wxT("Certificate Issuer"));
	sizer->Add(tc_provider, 0, wxLEFT|wxRIGHT|wxEXPAND, 10);
	tc_provider_info = new wxStaticText(this, ID_CRQ_PROVIDER_INFO, wxT(""), wxDefaultPosition,
		wxSize(0, em_h*5));
	sizer->Add(tc_provider_info, 0, wxALL|wxEXPAND, 10);
	int nprov = 0;
	if (tqsl_getNumProviders(&nprov))
		wxMessageBox(getLocalizedErrorString(), _("Error"), wxOK | wxICON_ERROR, this);
	for (int i = 0; i < nprov; i++) {
		TQSL_PROVIDER prov;
		if (!tqsl_getProvider(i, &prov))
			providers.push_back(prov);
	}
	sort(providers.begin(), providers.end(), prov_cmp);
	int selected = -1;
	for (int i = 0; i < static_cast<int>(providers.size()); i++) {
		tc_provider->Append(wxString::FromUTF8(providers[i].organizationName), reinterpret_cast<void *>(i));
		if (crq && !strcmp(providers[i].organizationName, crq->providerName)
			&& !strcmp(providers[i].organizationalUnitName, crq->providerUnit)) {
			selected = i;
		}
	}
	tc_provider->SetSelection((selected < 0) ? 0 : selected);
	if (providers.size() < 2 || selected >= 0)
		tc_provider->Enable(false);
	DoUpdateInfo();
	AdjustPage(sizer, wxT("crq.htm"));
}

void
CRQ_ProviderPage::DoUpdateInfo() {
	tqslTrace("CRQ_ProviderPage::DoUpdateInfo", NULL);
	int sel = tc_provider->GetSelection();
	if (sel >= 0) {
		long idx = (long)(tc_provider->GetClientData(sel));
		if (idx >=0 && idx < static_cast<int>(providers.size())) {
			Parent()->provider = providers[idx];
			wxString info;
			info = wxString::FromUTF8(Parent()->provider.organizationName);
			if (Parent()->provider.organizationalUnitName[0] != 0)
				info += wxString(wxT("\n  ")) + wxString::FromUTF8(Parent()->provider.organizationalUnitName);
			if (Parent()->provider.emailAddress[0] != 0)
				info += wxString(wxT("\n")) += _("Email: ") + wxString::FromUTF8(Parent()->provider.emailAddress);
			if (Parent()->provider.url[0] != 0)
				info += wxString(wxT("\n")) + _("URL: ") + wxString::FromUTF8(Parent()->provider.url);
			tc_provider_info->SetLabel(info);
		}
	}
}

void
CRQ_ProviderPage::UpdateInfo(wxCommandEvent&) {
	tqslTrace("CRQ_ProviderPage::UpdateInfo", NULL);
	DoUpdateInfo();
}


static wxDateTime::Month mons[] = {
	wxDateTime::Inv_Month, wxDateTime::Jan, wxDateTime::Feb, wxDateTime::Mar,
	wxDateTime::Apr, wxDateTime::May, wxDateTime::Jun, wxDateTime::Jul,
	wxDateTime::Aug, wxDateTime::Sep, wxDateTime::Oct, wxDateTime::Nov,
	wxDateTime::Dec };

BEGIN_EVENT_TABLE(CRQ_CallsignPage, CRQ_Page)
	EVT_TEXT(ID_CRQ_CALL, CRQ_Page::check_valid)
	EVT_TEXT(ID_CRQ_DXCC, tqslComboBox::OnTextEntry)
	EVT_TEXT(ID_CRQ_QBYEAR, tqslComboBox::OnTextEntry)
	EVT_TEXT(ID_CRQ_QBMONTH, tqslComboBox::OnTextEntry)
	EVT_TEXT(ID_CRQ_QBDAY, tqslComboBox::OnTextEntry)
	EVT_TEXT(ID_CRQ_QEYEAR, tqslComboBox::OnTextEntry)
	EVT_TEXT(ID_CRQ_QEMONTH, tqslComboBox::OnTextEntry)
	EVT_TEXT(ID_CRQ_QEDAY, tqslComboBox::OnTextEntry)
	EVT_COMBOBOX(ID_CRQ_DXCC, CRQ_Page::check_valid)
	EVT_COMBOBOX(ID_CRQ_QBYEAR, CRQ_Page::check_valid)
	EVT_COMBOBOX(ID_CRQ_QBMONTH, CRQ_Page::check_valid)
	EVT_COMBOBOX(ID_CRQ_QBDAY, CRQ_Page::check_valid)
	EVT_COMBOBOX(ID_CRQ_QEYEAR, CRQ_Page::check_valid)
	EVT_COMBOBOX(ID_CRQ_QEMONTH, CRQ_Page::check_valid)
	EVT_COMBOBOX(ID_CRQ_QEDAY, CRQ_Page::check_valid)
	EVT_CHECKBOX(ID_CRQ_SHOWALL, CRQ_CallsignPage::OnShowHide)
END_EVENT_TABLE()

CRQ_CallsignPage::CRQ_CallsignPage(CRQWiz *parent, TQSL_CERT_REQ *crq) :  CRQ_Page(parent) {
	tqslTrace("CRQ_CallsignPage::CRQ_CallsignPage", "parent=%lx, crq=%lx", reinterpret_cast<void *>(parent), reinterpret_cast<void *>(crq));
	initialized = false;
	_parent = parent;
	showAll = false;
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);

	wxStaticText *dst = new wxStaticText(this, -1, _("DXCC entity:"));
	wxSize sz = getTextSize(this);
	int em_h = sz.GetHeight();
	int em_w = sz.GetWidth();
	wxStaticText *st = new wxStaticText(this, -1, _("Call sign:"), wxDefaultPosition, wxDefaultSize,
		wxST_NO_AUTORESIZE|wxALIGN_RIGHT);
	st->SetSize(dst->GetSize());

	wxBoxSizer *hsizer = new wxBoxSizer(wxHORIZONTAL);
	hsizer->Add(st, 0, wxRIGHT|wxALIGN_CENTER_VERTICAL, 5);
	wxString cs;
	if (crq && crq->callSign[0])
		cs = wxString::FromUTF8(crq->callSign);
	tc_call = new wxTextCtrl(this, ID_CRQ_CALL, cs, wxDefaultPosition, wxSize(em_w*15, -1));
	tc_call->SetMaxLength(TQSL_CALLSIGN_MAX);
	ACCESSIBLE(tc_call, WindowAccessible);
	tc_call->SetName(wxT("Call sign"));
	hsizer->Add(tc_call, 0, wxEXPAND, 0);
	sizer->Add(hsizer, 0, wxLEFT|wxRIGHT|wxTOP|wxEXPAND, 10);
	if (crq && crq->callSign[0])
		tc_call->Enable(false);

	hsizer = new wxBoxSizer(wxHORIZONTAL);
	hsizer->Add(dst, 0, wxRIGHT|wxALIGN_CENTER_VERTICAL, 5);
#if  wxUSE_ACCESSIBILITY && __WXMAC__
	tc_dxcc = new tqslComboBox(this, ID_CRQ_DXCC, wxT(""), wxDefaultPosition,
		wxSize(em_w*25, -1), 0, 0, wxCB_DROPDOWN);
#else
	tc_dxcc = new tqslComboBox(this, ID_CRQ_DXCC, wxT(""), wxDefaultPosition,
		wxSize(em_w*25, -1), 0, 0, wxCB_DROPDOWN|wxCB_READONLY);
#endif
	hsizer->Add(tc_dxcc, 1, 0, 0);
	ACCESSIBLE(tc_dxcc, ComboBoxAx);
	tc_dxcc->SetName(wxT("DXCC Entity"));

        tc_showall = new wxCheckBox(this, ID_CRQ_SHOWALL, wxT("Show All Entities"));

	hsizer->Add(tc_showall);

	sizer->Add(hsizer, 0, wxALL, 10);

	DXCC dx;
	bool ok = dx.getFirst();
	while (ok) {
		wxString ename = entityNames[dx.number()];
		if (ename.IsEmpty())
			ename = wxString::FromUTF8(dx.name());
		tc_dxcc->Append(ename, reinterpret_cast<void *>(dx.number()));
		ok = dx.getNext();
	}

	const char *ent = "NONE";
	if (crq) {
		if (dx.getByEntity(crq->dxccEntity)) {
			if (entityNames[crq->dxccEntity].IsEmpty())
				ent = dx.name();
			else
				ent = entityNames[crq->dxccEntity].ToUTF8();
			tc_dxcc->Enable(false);
		}
	}
	int i = tc_dxcc->FindString(wxString::FromUTF8(ent));
	if (i >= 0)
		tc_dxcc->SetSelection(i);
	struct {
		tqslComboBox **cb;
		int id;
	} boxes[][3] = {
	    { {&tc_qsobeginy, ID_CRQ_QBYEAR}, {&tc_qsobeginm, ID_CRQ_QBMONTH}, {&tc_qsobegind, ID_CRQ_QBDAY} },
	    { {&tc_qsoendy, ID_CRQ_QEYEAR}, {&tc_qsoendm, ID_CRQ_QEMONTH}, {&tc_qsoendd, ID_CRQ_QEDAY} }
	};
	int year = wxDateTime::GetCurrentYear() + 1;

	int sels[2][3];
	int dates[2][3];
	if (crq) {
		dates[0][0] = crq->qsoNotBefore.year;
		dates[0][1] = crq->qsoNotBefore.month;
		dates[0][2] = crq->qsoNotBefore.day;
		dates[1][0] = crq->qsoNotAfter.year;
		dates[1][1] = crq->qsoNotAfter.month;
		dates[1][2] = crq->qsoNotAfter.day;
	}
	wxString label = _("Date of the first QSO you made or will make using this callsign:");
	for (int i = 0; i < 2; i++) {
		sels[i][0] = sels[i][1] = sels[i][2] = 0;
		sizer->Add(new wxStaticText(this, -1, label), 0, wxBOTTOM, 5);
		hsizer = new wxBoxSizer(wxHORIZONTAL);
		hsizer->Add(new wxStaticText(this, -1, wxT("Y")), 0, wxLEFT|wxALIGN_CENTER_VERTICAL, 20);
		*(boxes[i][0].cb) = new tqslComboBox(this, boxes[i][0].id, wxT(""), wxDefaultPosition,
			wxSize(em_w*8, -1), 0, 0, wxCB_DROPDOWN/*|wxCB_READONLY*/);
		hsizer->Add(*(boxes[i][0].cb), 0, wxLEFT, 5);
		ACCESSIBLE(*(boxes[i][0].cb), ComboBoxAx);
		(*boxes[i][0].cb)->SetName(i ? wxT("QSO End Year") : wxT("QSO Begin Year"));
		hsizer->Add(new wxStaticText(this, -1, wxT("M")), 0, wxLEFT|wxALIGN_CENTER_VERTICAL, 10);
		*(boxes[i][1].cb) = new tqslComboBox(this, boxes[i][1].id, wxT(""), wxDefaultPosition,
			wxSize(em_w*6, -1), 0, 0, wxCB_DROPDOWN/*|wxCB_READONLY*/);
		hsizer->Add(*(boxes[i][1].cb), 0, wxLEFT, 5);
		ACCESSIBLE(*(boxes[i][1].cb), ComboBoxAx);
		(*boxes[i][1].cb)->SetName(i ? wxT("QSO End Month") : wxT("QSO Begin Month"));
		hsizer->Add(new wxStaticText(this, -1, wxT("D")), 0, wxLEFT|wxALIGN_CENTER_VERTICAL, 10);
		*(boxes[i][2].cb) = new tqslComboBox(this, boxes[i][2].id, wxT(""), wxDefaultPosition,
			wxSize(em_w*6, -1), 0, 0, wxCB_DROPDOWN/*|wxCB_READONLY*/);
		hsizer->Add(*(boxes[i][2].cb), 0, wxLEFT, 5);
		ACCESSIBLE(*(boxes[i][2].cb), ComboBoxAx);
		(*boxes[i][2].cb)->SetName(i ? wxT("QSO End Day of Month") : wxT("QSO Begin Day of Month"));

		// for end-date boxes, add a blank entry at the top
		if (i > 0) {
			for (int j = 0; j < 3; j++)
				(*(boxes[i][j].cb))->Append(wxT(""));
		}
		for (int j = year; j >= 1945; j--) {
			wxString s;
			s.Printf(wxT("%d"), j);
			if (crq && dates[i][0] == j)
				sels[i][0] = year - j + i;
			(*(boxes[i][0].cb))->Append(s);
		}
		for (int j = 1; j <= 12; j++) {
			wxString s;
			s.Printf(wxT("%d"), j);
			if (crq && dates[i][1] == j)
				sels[i][1] = j - 1 + i;
			(*(boxes[i][1].cb))->Append(s);
		}
		for (int j = 1; j <= 31; j++) {
			wxString s;
			s.Printf(wxT("%d"), j);
			if (crq && dates[i][2] == j)
				sels[i][2] = j - 1 + i;
			(*(boxes[i][2].cb))->Append(s);
		}
		sizer->Add(hsizer, 0, wxLEFT|wxRIGHT, 10);
		if (i == 0)
			sizer->Add(0, 40);
		label = _("Date of the last QSO you made or will make using this callsign:\n(Leave this date blank if this is still your valid callsign.)");
	}
	if (crq) {
		tc_qsobeginy->SetSelection(sels[0][0]);
		tc_qsobeginm->SetSelection(sels[0][1]);
		tc_qsobegind->SetSelection(sels[0][2]);
		wxDateTime now = wxDateTime::Now();
		wxDateTime qsoEnd(crq->qsoNotAfter.day, mons[crq->qsoNotAfter.month],
			crq->qsoNotAfter.year, 23, 59, 59);
		if (qsoEnd < now) {
			_parent->expired = true;
			// Looks like this is a cert for an expired call sign,
			// so keep the QSO end date as-is. Otherwise, leave it
			// blank so CA can fill it in.
			tc_qsoendy->SetSelection(sels[1][0]);
			tc_qsoendm->SetSelection(sels[1][1]);
			tc_qsoendd->SetSelection(sels[1][2]);
		}
	}
	tc_cs_status = new wxStaticText(this, -1, wxT(""), wxDefaultPosition, wxSize(_parent->maxWidth, em_h*4));
	sizer->Add(tc_cs_status, 0, wxALL|wxEXPAND, 10);
	AdjustPage(sizer, wxT("crq0.htm"));
	initialized = true;
}

CRQ_Page *
CRQ_CallsignPage::GetNext() const {
	tqslTrace("CRQ_CallsignPage::GetNext", NULL);
	if (_parent->cert) {			// Renewal
		_parent->signIt = CRQ_SIGN_RENEWAL;
		reinterpret_cast<CRQ_NamePage*>(_parent->namePage)->Preset(reinterpret_cast<CRQ_CallsignPage*>(_parent->callsignPage));
		return _parent->namePage;
	}
	if (_parent->dxcc == 0) {		// NONE always requires signature
		_parent->signIt = CRQ_SIGN_NONE;
		return _parent->namePage;
	}
	if (_parent->onebyone) {		// 1x1 always requires signature
		_parent->signIt = CRQ_SIGN_1X1;
		return _parent->namePage;
	}
	if (!_parent->validcerts) {		// No certs, can't sign.
		_parent->signIt = CRQ_NOT_SIGNED;
		reinterpret_cast<CRQ_NamePage*>(_parent->namePage)->Preset(reinterpret_cast<CRQ_CallsignPage*>(_parent->callsignPage));
		return _parent->namePage;
	}
	if (_parent->portable) {		// Portable, no need to ask
		_parent->signIt = CRQ_SIGN_PORTABLE;
		reinterpret_cast<CRQ_NamePage*>(_parent->namePage)->Preset(reinterpret_cast<CRQ_CallsignPage*>(_parent->callsignPage));
		return _parent->namePage;
	}
	return _parent->typePage;
}

CRQ_Page *
CRQ_CallsignPage::GetPrev() const {
	tqslTrace("CRQ_CallsignPage::GetPrev", NULL);
	if (_parent->nprov > 1)
		return _parent->providerPage;
	return _parent->callsignPage;
}

void
CRQ_CallsignPage::ShowHide() {
        showAll = tc_showall->GetValue();
	validate();
}

BEGIN_EVENT_TABLE(CRQ_NamePage, CRQ_Page)
	EVT_TEXT(ID_CRQ_NAME, CRQ_Page::check_valid)
	EVT_TEXT(ID_CRQ_ADDR1, CRQ_Page::check_valid)
	EVT_TEXT(ID_CRQ_CITY, CRQ_Page::check_valid)
END_EVENT_TABLE()

CRQ_NamePage::CRQ_NamePage(CRQWiz *parent, TQSL_CERT_REQ *crq) :  CRQ_Page(parent) {
	tqslTrace("CRQ_NamePage::CRQ_NamePage", "parent=%lx, crq=%lx", reinterpret_cast<void *>(parent), reinterpret_cast<void *>(crq));
	initialized = false;
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);
	_parent = parent;

	wxStaticText *zst = new wxStaticText(this, -1, _("Zip/Postal"));

	wxSize sz = getTextSize(this);
	int em_w = sz.GetWidth();
	int def_w = em_w * 20;
	wxStaticText *st = new wxStaticText(this, -1, _("Name"), wxDefaultPosition, wxDefaultSize,
		wxST_NO_AUTORESIZE|wxALIGN_RIGHT);
	st->SetSize(zst->GetSize());

	wxConfig *config = reinterpret_cast<wxConfig *>(wxConfig::Get());
	wxString val;
	wxBoxSizer *hsizer = new wxBoxSizer(wxHORIZONTAL);
	hsizer->Add(st, 0, wxRIGHT|wxALIGN_CENTER_VERTICAL, 5);
	wxString s;
	if (crq && crq->name[0])
		s = wxString::FromUTF8(crq->name);
	else if (config->Read(wxT("Name"), &val))
		s = val;
	tc_name = new wxTextCtrl(this, ID_CRQ_NAME, s, wxDefaultPosition, wxSize(def_w, -1));
	ACCESSIBLE(tc_name, WindowAccessible);
	tc_name->SetName(wxT("Name"));
	hsizer->Add(tc_name, 1, 0, 0);
	sizer->Add(hsizer, 0, wxALL, 10);
	tc_name->SetMaxLength(TQSL_CRQ_NAME_MAX);

	s = wxT("");
	if (crq && crq->address1[0])
		s = wxString::FromUTF8(crq->address1);
	else if (config->Read(wxT("Addr1"), &val))
		s = val;
	hsizer = new wxBoxSizer(wxHORIZONTAL);
	hsizer->Add(new wxStaticText(this, -1, _("Address"), wxDefaultPosition, zst->GetSize(),
		wxST_NO_AUTORESIZE|wxALIGN_RIGHT), 0, wxRIGHT|wxALIGN_CENTER_VERTICAL, 5);
	tc_addr1 = new wxTextCtrl(this, ID_CRQ_ADDR1, s, wxDefaultPosition, wxSize(def_w, -1));
	ACCESSIBLE(tc_addr1, WindowAccessible);
	tc_addr1->SetName(wxT("Address line 1"));
	hsizer->Add(tc_addr1, 1, 0, 0);
	sizer->Add(hsizer, 0, wxLEFT|wxRIGHT|wxBOTTOM, 10);
	tc_addr1->SetMaxLength(TQSL_CRQ_ADDR_MAX);

	s = wxT("");
	if (crq && crq->address2[0])
		s = wxString::FromUTF8(crq->address2);
	else if (config->Read(wxT("Addr2"), &val))
		s = val;
	hsizer = new wxBoxSizer(wxHORIZONTAL);
	hsizer->Add(new wxStaticText(this, -1, wxT(""), wxDefaultPosition, zst->GetSize(),
		wxST_NO_AUTORESIZE|wxALIGN_RIGHT), 0, wxRIGHT, 5);
	tc_addr2 = new wxTextCtrl(this, ID_CRQ_ADDR2, s, wxDefaultPosition, wxSize(def_w, -1));
	ACCESSIBLE(tc_addr2, WindowAccessible);
	tc_addr2->SetName(wxT("Address line 2"));
	hsizer->Add(tc_addr2, 1, 0, 0);
	sizer->Add(hsizer, 0, wxLEFT|wxRIGHT|wxBOTTOM, 10);
	tc_addr2->SetMaxLength(TQSL_CRQ_ADDR_MAX);

	s = wxT("");
	if (crq && crq->city[0])
		s = wxString::FromUTF8(crq->city);
	else if (config->Read(wxT("City"), &val))
		s = val;
	hsizer = new wxBoxSizer(wxHORIZONTAL);
	hsizer->Add(new wxStaticText(this, -1, _("City"), wxDefaultPosition, zst->GetSize(),
		wxST_NO_AUTORESIZE|wxALIGN_RIGHT), 0, wxRIGHT|wxALIGN_CENTER_VERTICAL, 5);
	tc_city = new wxTextCtrl(this, ID_CRQ_CITY, s, wxDefaultPosition, wxSize(def_w, -1));
	ACCESSIBLE(tc_city, WindowAccessible);
	tc_city->SetName(wxT("City"));
	hsizer->Add(tc_city, 1, 0, 0);
	sizer->Add(hsizer, 0, wxLEFT|wxRIGHT|wxBOTTOM, 10);
	tc_city->SetMaxLength(TQSL_CRQ_CITY_MAX);

	s = wxT("");
	if (crq && crq->state[0])
		s = wxString::FromUTF8(crq->state);
	else if (config->Read(wxT("State"), &val))
		s = val;
	hsizer = new wxBoxSizer(wxHORIZONTAL);
	hsizer->Add(new wxStaticText(this, -1, _("State"), wxDefaultPosition, zst->GetSize(),
		wxST_NO_AUTORESIZE|wxALIGN_RIGHT), 0, wxRIGHT|wxALIGN_CENTER_VERTICAL, 5);
	tc_state = new wxTextCtrl(this, ID_CRQ_STATE, s, wxDefaultPosition, wxSize(def_w, -1));
	ACCESSIBLE(tc_state, WindowAccessible);
	tc_state->SetName(wxT("State"));
	hsizer->Add(tc_state, 1, 0, 0);
	sizer->Add(hsizer, 0, wxLEFT|wxRIGHT|wxBOTTOM, 10);
	tc_state->SetMaxLength(TQSL_CRQ_STATE_MAX);

	s = wxT("");
	if (crq && crq->postalCode[0])
		s = wxString::FromUTF8(crq->postalCode);
	else if (config->Read(wxT("ZIP"), &val))
		s = val;
	hsizer = new wxBoxSizer(wxHORIZONTAL);
	hsizer->Add(zst, 0, wxRIGHT|wxALIGN_CENTER_VERTICAL, 5);
	tc_zip = new wxTextCtrl(this, ID_CRQ_ZIP, s, wxDefaultPosition, wxSize(def_w, -1));
	hsizer->Add(tc_zip, 1, 0, 0);
	ACCESSIBLE(tc_zip, WindowAccessible);
	tc_zip->SetName(wxT("ZIP"));
	sizer->Add(hsizer, 0, wxLEFT|wxRIGHT|wxBOTTOM, 10);
	tc_zip->SetMaxLength(TQSL_CRQ_POSTAL_MAX);

	s = wxT("");
	if (crq && crq->country[0])
		s = wxString::FromUTF8(crq->country);
	else if (config->Read(_("Country"), &val))
		s = val;
	hsizer = new wxBoxSizer(wxHORIZONTAL);
	hsizer->Add(new wxStaticText(this, -1, _("Country"), wxDefaultPosition, zst->GetSize(),
		wxST_NO_AUTORESIZE|wxALIGN_RIGHT), 0, wxRIGHT|wxALIGN_CENTER_VERTICAL, 5);
	tc_country = new wxTextCtrl(this, ID_CRQ_COUNTRY, s, wxDefaultPosition, wxSize(def_w, -1));
	ACCESSIBLE(tc_country, WindowAccessible);
	tc_country->SetName(wxT("Country"));
	hsizer->Add(tc_country, 1, 0, 0);
	sizer->Add(hsizer, 0, wxLEFT|wxRIGHT|wxBOTTOM, 10);
	tc_country->SetMaxLength(TQSL_CRQ_COUNTRY_MAX);
	tc_addr_status = new wxStaticText(this, -1, wxT(""));
	sizer->Add(tc_addr_status, 0, wxALL|wxEXPAND, 10);
	AdjustPage(sizer, wxT("crq1.htm"));
	initialized = true;
}

void
CRQ_NamePage::Preset(CRQ_CallsignPage *ip) {
	wxString s;
	string t;
	if (!_parent->networkError) {
		if (SaveAddressInfo(_parent->callsign.ToUTF8(), _parent->dxcc) < 0) {	// Timeout, net error
			_parent->networkError = true;
		}
	}
	if (!_parent->name.IsEmpty()) {
		tc_name->SetValue(_parent->name);
	} else if (get_address_field(_parent->callsign.ToUTF8(), "name", t) == 0) {
		s = wxString::FromUTF8(t.c_str());
		tc_name->SetValue(s);
	}

	if (!_parent->addr1.IsEmpty()) {
		tc_addr1->SetValue(_parent->addr1);
	} else if (get_address_field(_parent->callsign.ToUTF8(), "addr1", t) == 0) {
		s = wxString::FromUTF8(t.c_str());
		tc_addr1->SetValue(s);
	}
	if (!_parent->addr2.IsEmpty()) {
		if (_parent->addr2 == wxT("."))
			_parent->addr2 = wxT("");
		tc_addr2->SetValue(_parent->addr2);
	} else if (get_address_field(_parent->callsign.ToUTF8(), "addr2", t) == 0) {
		s = wxString::FromUTF8(t.c_str());
		tc_addr2->SetValue(s);
	}
	if (!_parent->city.IsEmpty()) {
		tc_city->SetValue(_parent->city);
	} else if (get_address_field(_parent->callsign.ToUTF8(), "city", t) == 0) {
		s = wxString::FromUTF8(t.c_str());
		tc_city->SetValue(s);
	}
	if (!_parent->state.IsEmpty()) {
		tc_state->SetValue(_parent->state);
	} else if (get_address_field(_parent->callsign.ToUTF8(), "addrState", t) == 0) {
		s = wxString::FromUTF8(t.c_str());
		tc_state->SetValue(s);
	}
	if (!_parent->zip.IsEmpty()) {
		tc_zip->SetValue(_parent->zip);
	} else if (get_address_field(_parent->callsign.ToUTF8(), "mailCode", t) == 0) {
		s = wxString::FromUTF8(t.c_str());
		tc_zip->SetValue(s);
	}
	if (!_parent->country.IsEmpty()) {
		tc_country->SetValue(_parent->country);
	} else if (get_address_field(_parent->callsign.ToUTF8(), "aCountry", t) == 0) {
		s = wxString::FromUTF8(t.c_str());
		tc_country->SetValue(s);
	}
}

CRQ_Page *
CRQ_NamePage::GetNext() const {
	tqslTrace("CRQ_NamePage::GetNext", NULL);
	return _parent->emailPage;
}

CRQ_Page *
CRQ_NamePage::GetPrev() const {
	tqslTrace("CRQ_NamePage::GetPrev", NULL);
	if ((_parent->dxcc == 0) || _parent->onebyone || _parent->portable)
		return _parent->callsignPage;
	if (_parent->validcerts)
		return _parent->typePage;
	return _parent->callsignPage;
}


BEGIN_EVENT_TABLE(CRQ_EmailPage, CRQ_Page)
	EVT_TEXT(ID_CRQ_EMAIL, CRQ_Page::check_valid)
END_EVENT_TABLE()

CRQ_EmailPage::CRQ_EmailPage(CRQWiz *parent, TQSL_CERT_REQ *crq) :  CRQ_Page(parent) {
	tqslTrace("CRQ_EmailPage::CRQ_EmailPage", "parent=%lx, crq=%lx", reinterpret_cast<void *>(parent), reinterpret_cast<void *>(crq));
	initialized = false;
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);

	_parent = parent;
	wxSize sz = getTextSize(this);
	int em_w = sz.GetWidth();
	wxStaticText *st = new wxStaticText(this, -1, _("Your e-mail address"));

	wxConfig *config = reinterpret_cast<wxConfig *>(wxConfig::Get());
	wxString val;
	wxString s;
	if (crq && crq->emailAddress[0])
		s = wxString::FromUTF8(crq->emailAddress);
	else if (config->Read(wxT("Email"), &val))
		s = val;
	sizer->Add(st, 0, wxLEFT|wxRIGHT|wxTOP, 10);
	tc_email = new wxTextCtrl(this, ID_CRQ_EMAIL, s, wxDefaultPosition, wxSize(em_w*30, -1));
	sizer->Add(tc_email, 0, wxLEFT|wxRIGHT|wxBOTTOM, 10);
	tc_email->SetMaxLength(TQSL_CRQ_EMAIL_MAX);
	ACCESSIBLE(tc_email, WindowAccessible);
	tc_email->SetName(wxT("e-mail"));
	wxStaticText *tc_warn = new wxStaticText(this, -1, _("Note: The e-mail address you provide here is the address to which the issued Certificate will be sent. Make sure it's the correct address!"));
	sizer->Add(tc_warn, 0, wxALL, 10);
	tc_warn->Wrap(_parent->maxWidth);
	tc_em_status = new wxStaticText(this, -1, wxT(""));
	sizer->Add(tc_em_status, 0, wxALL|wxEXPAND, 10);
	AdjustPage(sizer, wxT("crq2.htm"));
	initialized = true;
}

CRQ_Page *
CRQ_EmailPage::GetNext() const {
	tqslTrace("CRQ_EmailPage::GetNext", NULL);
	if (_parent->CertPwd) {
		return _parent->pwPage;
	} else {
		if (_parent->ShouldBeSigned()) {
			return _parent->signPage;
		} else {
			return NULL;
		}
	}
	return NULL;
}

CRQ_Page *
CRQ_EmailPage::GetPrev() const {
	tqslTrace("CRQ_EmailPage::GetPrev", NULL);

	return _parent->namePage;
}

BEGIN_EVENT_TABLE(CRQ_PasswordPage, CRQ_Page)
	EVT_TEXT(ID_CRQ_PW1, CRQ_Page::check_valid)
	EVT_TEXT(ID_CRQ_PW2, CRQ_Page::check_valid)
END_EVENT_TABLE()

CRQ_PasswordPage::CRQ_PasswordPage(CRQWiz *parent) :  CRQ_Page(parent) {
	tqslTrace("CRQ_PasswordPage::CRQ_PasswordPage", "parent=%lx", reinterpret_cast<void *>(parent));
	initialized = false;
	_parent = parent;

	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);

	wxSize sz = getTextSize(this);
	em_w = sz.GetWidth();
	em_h = sz.GetHeight();
	wxString lbl = _("You may protect this Callsign Certificate using a passphrase. If you are using a computer system that is shared with others, you should specify a passphrase to protect this Callsign Certificate. However, if you are using a computer in a private residence, no passphrase need be specified.");
	wxStaticText *st = new wxStaticText(this, -1, lbl);
	st->SetSize(_parent->maxWidth, em_h * 5);
	st->Wrap(_parent->maxWidth);
	sizer->Add(st, 0, wxLEFT|wxRIGHT|wxTOP, 10);
	fwdPrompt = new wxStaticText(this, -1, _("Leave the passphrase blank and click 'Next' unless you want to use a passphrase."));
	fwdPrompt->SetSize(_parent->maxWidth, em_h * 5);
	fwdPrompt->Wrap(_parent->maxWidth);
	sizer->Add(fwdPrompt, 0, wxLEFT|wxRIGHT|wxTOP, 10);
	sizer->Add(new wxStaticText(this, -1, _("Passphrase:")),
		0, wxLEFT|wxRIGHT|wxTOP, 10);
	tc_pw1 = new wxTextCtrl(this, ID_CRQ_PW1, wxT(""), wxDefaultPosition, wxSize(em_w*20, -1), wxTE_PASSWORD);
	tc_pw1->SetName(wxT("Passphrase"));
	ACCESSIBLE(tc_pw1, WindowAccessible);
	sizer->Add(tc_pw1, 0, wxLEFT|wxRIGHT, 10);
	sizer->Add(new wxStaticText(this, -1, _("Enter the passphrase again for verification:")),
		0, wxLEFT|wxRIGHT|wxTOP, 10);
	tc_pw2 = new wxTextCtrl(this, ID_CRQ_PW2, wxT(""), wxDefaultPosition, wxSize(em_w*20, -1), wxTE_PASSWORD);
	ACCESSIBLE(tc_pw2, WindowAccessible);
	tc_pw2->SetName(wxT("Repeat the Passphrase"));
	sizer->Add(tc_pw2, 0, wxLEFT|wxRIGHT, 10);
	wxStaticText *tc_pwwarn = new wxStaticText(this, -1, _("DO NOT lose the passphrase you choose! You will be unable to use the Certificate without this passphrase!"));
	tc_pwwarn->Wrap(em_w * 40);
	sizer->Add(tc_pwwarn, 0, wxALL, 10);
	tc_pwd_status = new wxStaticText(this, -1, wxT(""));
	sizer->Add(tc_pwd_status, 0, wxALL|wxEXPAND, 10);
	AdjustPage(sizer, wxT("crq3.htm"));
	initialized = true;
}

CRQ_Page *
CRQ_PasswordPage::GetNext() const {
	tqslTrace("CRQ_PasswordPage::GetNext", NULL);
	if (_parent->ShouldBeSigned()) {
		fwdPrompt->SetLabel(_("Leave the passphrase blank and click 'Next' unless you want to use a passphrase."));
		fwdPrompt->SetSize(_parent->maxWidth, em_h * 5);
		fwdPrompt->Wrap(_parent->maxWidth);
		return _parent->signPage;
	} else {
		fwdPrompt->SetLabel(_("Leave the passphrase blank and click 'Finish' unless you want to use a passphrase."));
		fwdPrompt->SetSize(_parent->maxWidth, em_h * 5);
		fwdPrompt->Wrap(_parent->maxWidth);
		return NULL;
	}
}

CRQ_Page *
CRQ_PasswordPage::GetPrev() const {
	tqslTrace("CRQ_PasswordPage::GetPrev", NULL);
	return _parent->emailPage;
}

BEGIN_EVENT_TABLE(CRQ_TypePage, CRQ_Page)
	EVT_RADIOBOX(ID_CRQ_TYPE, CRQ_Page::check_valid)
END_EVENT_TABLE()

CRQ_TypePage::CRQ_TypePage(CRQWiz *parent)
	:  CRQ_Page(parent) {
	tqslTrace("CRQ_TypePage::CRQ_TypePage", "parent=%lx", reinterpret_cast<void *>(parent));

	initialized = false;
	_parent = parent;

	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);

	wxArrayString ch;
	for (unsigned int i = 0; i < sizeof callTypeChoices / sizeof callTypeChoices[0]; i++) {
		ch.Add(wxGetTranslation(callTypeChoices[i]));
	}

	certType = new wxRadioBox(this, ID_CRQ_TYPE, _("What is this Callsign Certificate for?"), wxDefaultPosition,
		wxDefaultSize, ch, 1, wxRA_SPECIFY_COLS);

	sizer->Add(certType, 0, wxALL|wxEXPAND, 10);
}

bool
CRQ_TypePage::TransferDataFromWindow() {
	static int signThisType[] = {
		CRQ_SIGN_REPLACEMENT,	// Replaces former call
		CRQ_SIGN_REPLACEMENT,	// Is former call
		CRQ_SIGN_QSL_MGR,	// QSL manager
		CRQ_SIGN_QSL_MGR,	// Club
		CRQ_SIGN_QSL_MGR,	// DXpedition
		CRQ_SIGN_SPC_EVENT,	// Special event
		CRQ_SIGN_MAYBE,		// None of the above
		0
	};

	tqslTrace("CRQ_TypePage::TransferDataFromWindow", NULL);
	int selected = certType->GetSelection();
	if (selected  == wxNOT_FOUND || selected > static_cast<int>(sizeof signThisType / sizeof signThisType[0]))
		return false;
	_parent->signIt = signThisType[selected];
	_parent->certType = selected;
	if (_parent->dxcc == 0)
		_parent->signIt = CRQ_SIGN_NONE;
	return true;
}

CRQ_Page *
CRQ_TypePage::GetPrev() const {
	tqslTrace("CRQ_TypePage::GetPrev", NULL);

	if (_parent->nprov > 1)
		return _parent->providerPage;
	else
		return _parent->callsignPage;
}

CRQ_Page *
CRQ_TypePage::GetNext() const {
	tqslTrace("CRQ_TypePage::GetNext", NULL);

	return _parent->namePage;
}

BEGIN_EVENT_TABLE(CRQ_SignPage, CRQ_Page)
	EVT_TREE_SEL_CHANGED(ID_CRQ_CERT, CRQ_SignPage::CertSelChanged)
	EVT_RADIOBOX(ID_CRQ_SIGN, CRQ_Page::check_valid)
	EVT_WIZARD_PAGE_CHANGING(wxID_ANY, CRQ_SignPage::OnPageChanging)
END_EVENT_TABLE()


void CRQ_SignPage::CertSelChanged(wxTreeEvent& event) {
	tqslTrace("CRQ_SignPage::CertSelChanged", NULL);
	if (cert_tree->GetItemData(event.GetItem()))
		_parent->signIt = CRQ_SIGN_MAYBE;
	wxCommandEvent dummy;
	check_valid(dummy);
}

CRQ_SignPage::CRQ_SignPage(CRQWiz *parent, TQSL_CERT_REQ *crq)
	:  CRQ_Page(parent) {
	tqslTrace("CRQ_SignPage::CRQ_SignPage", "parent=%lx", reinterpret_cast<void *>(parent));

	initialized = false;
	wxSize sz = getTextSize(this);
	em_h = sz.GetHeight();
	em_w = sz.GetWidth();

	_parent = parent;
	wxBoxSizer *sizer = new wxBoxSizer(wxVERTICAL);

	introText = new wxStaticText(this, -1, wxT(""), wxDefaultPosition, wxSize(em_w * 50, em_h * 8));
	sizer->Add(introText);
	introText->Wrap(_parent->maxWidth);

	tc_sign_status = new wxStaticText(this, -1, wxT(""), wxDefaultPosition, wxSize(_parent->maxWidth, em_h*3));

	cert_tree = new CertTree(this, ID_CRQ_CERT, wxDefaultPosition,
		wxSize(em_w*30, em_h*8), wxTR_HAS_BUTTONS | wxSUNKEN_BORDER);
	sizer->Add(cert_tree, 0, wxLEFT|wxRIGHT|wxBOTTOM|wxEXPAND);
	cert_tree->SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOW));
	ACCESSIBLE(cert_tree, TreeCtrlAx);
	sizer->Add(tc_sign_status, 0, wxALL|wxEXPAND, 10);
	// Default to 'signed' unless there's no valid certificates to use for signing.
	if (cert_tree->Build(0, &(_parent->provider)) > 0) {
		_parent->signIt = CRQ_NOT_SIGNED;
		cert_tree->Show(false);
		introContent = _("Since you have no Callsign Certificates, you must "
					"submit an 'Unsigned' certificate request. This will allow you to "
					"create your initial Callsign Certificate for LoTW use. "
					"Click 'Finish' to complete this Callsign Certificate request.");
		introText->SetLabel(introContent);
	}
	introText->Wrap(em_w * 50);
	AdjustPage(sizer, wxT("crq4.htm"));
	initialized = true;
}

void
CRQ_SignPage::refresh() {
	tqslTrace("CRQ_SignPage::refresh", NULL);
	if (cert_tree->Build(0, &(_parent->provider)) > 0 || _parent->ShouldBeSigned()) {
		cert_tree->Show(true);
		if (_parent->MustBeSigned()) {
			wxString it(wxT("\n\n\n"));
			it += _("This Callsign Certificate request requires approval using an existing Callsign Certificate.");
			introText->SetLabel(it);
		} else {
			wxString introContent = wxString(_("Is this new certificate for a callsign where you already have a LoTW account, and you want the QSOs for this call to be added to an existing LoTW account? "));
        		introContent += wxT("\n\n");
			introContent += _("If so, choose a callsign below for the primary LoTW account. If not, click 'Finish', and a new LoTW account will be set up for these QSOs.");

			introContent += wxT("\n\n");
			introContent += _("CAUTION: Mixing QSOs for unrelated callsigns into one LoTW account can cause issues with handling awards.");
			introText->SetLabel(introContent);
		}
		introText->Wrap(em_w * 50);
	} else {
		// No certificates
		_parent->signIt = CRQ_NOT_SIGNED;
		introText->SetLabel(introContent);
		introText->Wrap(_parent->maxWidth);
	}
}

CRQ_Page *
CRQ_SignPage::GetPrev() const {
	tqslTrace("CRQ_SignPage::GetPrev", NULL);

	if (_parent->CertPwd)
		return _parent->pwPage;
	else
		return _parent->emailPage;
}

// Page validation

bool
CRQ_ProviderPage::TransferDataFromWindow() {
	// Nothing to validate
	return true;
}

static bool
validCallSign(const string& call) {
	// Check for invalid characters
	if (call.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/") != string::npos)
		return false;
	// Need at least one letter
	if (call.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ") == string::npos)
		return false;
	// Need at least one number
	size_t num;
	if ((num = call.find_first_of("0123456789")) == string::npos)
		return false;
	// At least one letter after the number - catches "/KP4" for example
	if (call.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ", num) == string::npos)
		return false;
	return true;
}

static bool
validPrefix(const string& prefix) {
	wxRegEx r;
	prefixMap::iterator it;
	for (it = prefixRegex.begin(); it != prefixRegex.end(); it++) {
		if (it->second.IsEmpty())
			continue;
		wxString p = it->second + wxT("\\d*$");
		if (r.Compile(p, wxRE_EXTENDED) && r.Matches(wxString::FromUTF8(prefix.c_str()))) {
			return true;
		}
	}
	return false;
}

const char *
CRQ_CallsignPage::validate() {
	tqslTrace("CRQ_CallsignPage::validate", NULL);
	tQSL_Cert *certlist = 0;
	int ncert = 0;
	DXCC dx;
	bool dxok;
	wxRegEx r;
	wxString prefix;
	vector<int> allowedDXCC;
	wxArrayString bits;
	wxString callsign;
	const char *dxccname = NULL;
	bool ok = true;

	if (!initialized)
		return 0;
#ifdef DEBUG
	while (1) {
		std::ifstream lotsacalls("callsigns.txt");
		string call;
		while(lotsacalls >> call) {
			_parent->callsign = call;
#else
	_parent->callsign = tc_call->GetValue().MakeUpper();
#endif

	valMsg = wxT("");
	if (tc_call->GetValue().Len() > TQSL_CALLSIGN_MAX) {
		valMsg = wxString::Format(_("The callsign is too long. Only %d characters are allowed."), TQSL_CALLSIGN_MAX);
		tc_cs_status->SetLabel(valMsg);
		tc_cs_status->Wrap(_parent->maxWidth);
		return 0;
	}

	// First check if there's a slash. If so, it's a portable. Use the base callsign
	_parent->portable = false;
	callsign = _parent->callsign;
	_parent->modifier = wxT("");
	_parent->home_call = callsign;

	if (!callsign.IsEmpty()) {
		bits.Clear();
		wxStringTokenizer callsplitter(_parent->callsign, wxT("/"));
		while (callsplitter.CountTokens() > 0) {
			wxString temp = callsplitter.GetNextToken();
			if ((temp == wxT("F") || temp == wxT("I") || temp == wxT("M") ||
			    temp.size() >= 2) &&
			   (temp != wxT("MM") && temp != wxT("QRP"))) {
				bits.Add(temp);
			}
		}

		switch (bits.GetCount()) {
			case 0:				// Single char or MM - nothing to see.
				break;
			case 1:
				_parent->home_call = bits[0];
				_parent->modifier = wxT("");
				break;
			case 2:
				_parent->home_call = bits[1];	// Assumes P5/W1AW
				_parent->modifier = bits[0];
				break;
			default:				// more than one slash, give up
				break;
		}
	}

	_parent->usa = false;					// Assume not USA

	// Shuffle time. Is one of these a valid callsign?
	if (!_parent->modifier.IsEmpty()) {
		// Is this Home/mod or mod/home ?
		if (validCallSign(std::string(_parent->modifier.mb_str())) && validPrefix(std::string(_parent->home_call.mb_str()))) {
			_parent->modifier = bits[1];	// Flip them as it's P5/W1AW
			_parent->home_call = bits[0];
		}
		_parent->portable = true;
		_parent->signIt = CRQ_SIGN_PORTABLE;
		if (isUSCallsign(_parent->modifier)) {
			_parent->usa = true;
		}
	} else {
		_parent->portable = false;
		if (isUSCallsign(_parent->home_call)) {
			_parent->usa = true;
		}
	}
#ifdef DEBUG
		std::cout << "callsign " <<_parent->callsign << " prefix " << _parent->modifier << " base " << _parent->home_call;
#endif
	int sel;

	_parent->onebyone = false;
	if (_parent->callsign.Len() < 3)
		ok = false;
	if (ok) {
		string call = string(_parent->callsign.ToUTF8());
		// Check for invalid characters
		if (call.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/") != string::npos)
			ok = false;
		// Need at least one letter
		if (call.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ") == string::npos)
			ok = false;
		// Need at least one number
		if (call.find_first_of("0123456789") == string::npos)
			ok = false;
		// Invalid callsign patterns
		// Starting with 0, Q, (no longer: C7, or 4Y)
		// 1x other than 1A, 1M, 1S
		string first = call.substr(0, 1);
		string second = call.substr(1, 1);
		string third = call.substr(2, 1);
		if (first == "0" || first == "Q" ||
		    (first == "1" && second != "A" && second != "M" && second != "S"))
			ok = false;
		if (call.size() == 3 &&
		    (first == "W" || first == "K" || first == "N") &&
		    (second >= "0" && second <= "9") &&
		    (third != "X")) {
			_parent->onebyone = true;
		}
	}

	if (!ok) {
		valMsg = _("You must enter a valid call sign.");
		tc_dxcc->Clear();
		goto notok;
	}

#ifndef DEBUG
	sel = tc_dxcc->GetSelection();
	if (sel >= 0)
		_parent->dxcc = (long)(tc_dxcc->GetClientData(sel));
	tc_dxcc->Clear();
#endif
	int found;
	found = -1;

	prefix = _parent->home_call;
	if (!_parent->modifier.IsEmpty()) {
		prefix = _parent->modifier;
	}

#ifdef DEBUG
	DXCC dx;
#endif
	if (!showAll) {
		prefixMap::iterator it;
		for (it = prefixRegex.begin(); it != prefixRegex.end(); it++) {
#ifndef DEBUG
			if (_parent->usa && isUSEntity(it->first)) {
					allowedDXCC.push_back(it->first);
			} else {
#else
{
#endif
				if (it->second.IsEmpty())
					continue;
				if (r.Compile(it->second, wxRE_EXTENDED) && r.Matches(prefix)) {
#ifdef DEBUG
					dx.getByEntity(it->first);
					std::cout << " " << it->first << ":" << entityNames[it->first];
#endif
					allowedDXCC.push_back(it->first);
				}
			}
		}
	}
#ifdef DEBUG
	std::cout << std::endl;
		}
		lotsacalls.close();
		exit(0);
	}
#else
	dxok = dx.getFirst();
	while (dxok) {
		if (showAll || allowedDXCC.size() == 0 || dx.number() == 0) {
			wxString ename = entityNames[dx.number()];
			if (ename.IsEmpty())
				ename = wxString::FromUTF8(dx.name());
			tc_dxcc->Append(ename, reinterpret_cast<void *>(dx.number()));
			if (sel >= 0 && dx.number() == _parent->dxcc) {
				found = tc_dxcc->GetCount() - 1;
			}
			dxok = dx.getNext();
			continue;
		}
		for (size_t i = 0; i < allowedDXCC.size(); i++) {
			if (allowedDXCC[i] == dx.number()) {
				wxString ename = entityNames[dx.number()];
				if (ename.IsEmpty())
					ename = wxString::FromUTF8(dx.name());
				tc_dxcc->Append(ename, reinterpret_cast<void *>(dx.number()));
				break;
			}
		}
		if (sel >= 0 && dx.number() == _parent->dxcc) {
			found = tc_dxcc->GetCount() - 1;
		}
		dxok = dx.getNext();
	}

	if (found >= 0) {
		tc_dxcc->SetSelection(found);
	} else {
		tc_dxcc->SetSelection(1);
	}

	long old_dxcc;
	old_dxcc = _parent->dxcc;

	tQSL_Date oldStartDate;
	tQSL_Date oldEndDate;
	tQSL_Date startDate;
	tQSL_Date endDate;
	tqsl_getDXCCStartDate(old_dxcc, &oldStartDate);
	tqsl_getDXCCEndDate(old_dxcc, &oldEndDate);
	sel = tc_dxcc->GetSelection();
	if (sel >= 0)
		_parent->dxcc = (long)(tc_dxcc->GetClientData(sel));

	tqsl_getDXCCStartDate(_parent->dxcc, &startDate);
	tqsl_getDXCCEndDate(_parent->dxcc, &endDate);

	if (sel < 0 || _parent->dxcc < 0) {
		valMsg = _("You must select a DXCC entity.");
		goto notok;
	}

	if (_parent->dxcc != old_dxcc) {
		if (tqsl_isDateValid(&startDate) && !tqsl_isDateNull(&startDate) &&
		    tqsl_compareDates(&_parent->qsonotbefore, &oldStartDate) == 0) {
			tc_qsobeginy->SetSelection(startDate.year - 1945);
			tc_qsobeginm->SetSelection(startDate.month - 1);
			tc_qsobegind->SetSelection(startDate.day - 1);
		}
		if ((tqsl_isDateValid(&endDate) || tqsl_isDateNull(&endDate)) &&
		     tqsl_compareDates(&_parent->qsonotafter, &oldEndDate) == 0) {
			if (tqsl_isDateNull(&endDate)) {
				tc_qsoendy->SetSelection(0);
				tc_qsoendm->SetSelection(0);
				tc_qsoendd->SetSelection(0);
			} else {
				tc_qsoendy->SetSelection(endDate.year - 1944);
				tc_qsoendm->SetSelection(endDate.month);
				tc_qsoendd->SetSelection(endDate.day);
			}
		}
	}
	_parent->qsonotbefore.year = strtol(tc_qsobeginy->GetValue().ToUTF8(), NULL, 10);
	_parent->qsonotbefore.month = strtol(tc_qsobeginm->GetValue().ToUTF8(), NULL, 10);
	_parent->qsonotbefore.day = strtol(tc_qsobegind->GetValue().ToUTF8(), NULL, 10);
	_parent->qsonotafter.year = strtol(tc_qsoendy->GetValue().ToUTF8(), NULL, 10);
	_parent->qsonotafter.month = strtol(tc_qsoendm->GetValue().ToUTF8(), NULL, 10);
	_parent->qsonotafter.day = strtol(tc_qsoendd->GetValue().ToUTF8(), NULL, 10);
	if (!tqsl_isDateValid(&_parent->qsonotbefore)) {
		valMsg = _("QSO begin date: You must choose proper values for Year, Month and Day.");
		goto notok;
	}
	if (!tqsl_isDateNull(&_parent->qsonotafter) && !tqsl_isDateValid(&_parent->qsonotafter)) {
		valMsg = _("QSO end date: You must either choose proper values for Year, Month and Day or leave all three blank.");
		goto notok;
	}
	if (tqsl_isDateValid(&_parent->qsonotbefore) && tqsl_isDateValid(&_parent->qsonotafter)
		&& tqsl_compareDates(&_parent->qsonotbefore, &_parent->qsonotafter) > 0) {
		valMsg = _("QSO end date cannot be before QSO begin date.");
		goto notok;
	}
	char startStr[50], endStr[50];
	tqsl_convertDateToText(&endDate, endStr, sizeof endStr);
	if (tqsl_getDXCCEntityName(_parent->dxcc, &dxccname))
		dxccname = "UNKNOWN";
	if (!tqsl_isDateValid(&startDate)) {
		startDate.year = 1945; startDate.month = 11; startDate.day = 1;
	}
	tqsl_convertDateToText(&startDate, startStr, sizeof startStr);

	if (tqsl_isDateValid(&endDate) && tqsl_isDateNull(&_parent->qsonotafter)) {
		_parent->qsonotafter = endDate;
		if (tqsl_isDateNull(&endDate)) {
			tc_qsoendy->SetSelection(0);
			tc_qsoendm->SetSelection(0);
			tc_qsoendd->SetSelection(0);
		} else {
			tc_qsoendy->SetSelection(endDate.year - 1944);
			tc_qsoendm->SetSelection(endDate.month);
			tc_qsoendd->SetSelection(endDate.day);
		}
	}

	if (tqsl_isDateValid(&endDate)) {
		tqsl_convertDateToText(&endDate, endStr, sizeof endStr);
	} else {
		endStr[0] = '\0';
	}

	if (tqsl_isDateValid(&startDate) && tqsl_compareDates(&_parent->qsonotbefore, &startDate) < 0) {
		valMsg = wxString::Format(_("The date of your first QSO is before the first valid date (%hs) of the selected DXCC Entity %hs"), startStr, dxccname);
		goto notok;
	}
	if (tqsl_isDateValid(&endDate) && tqsl_compareDates(&_parent->qsonotbefore, &endDate) > 0) {
		valMsg = wxString::Format(_("The date of your first QSO is after the last valid date (%hs) of the selected DXCC Entity %hs"), endStr, dxccname);
		goto notok;
	}
	if (tqsl_isDateValid(&startDate) && !tqsl_isDateNull(&_parent->qsonotafter) && tqsl_compareDates(&_parent->qsonotafter, &startDate) < 0) {
		valMsg = wxString::Format(_("The date of your last QSO is before the first valid date (%hs) of the selected DXCC Entity %hs"), startStr, dxccname);
		goto notok;
	}
	if (tqsl_isDateValid(&endDate) && tqsl_compareDates(&_parent->qsonotafter, &endDate) > 0) {
		valMsg = wxString::Format(_("The date of your last QSO is after the last valid date (%hs) of the selected DXCC Entity %hs"), endStr, dxccname);
		goto notok;
	}

	_parent->callsign.MakeUpper();
	// Check for US 1x1 callsigns
	_parent->usa = false;
	for (int i = 0; USEntities[i] > 0; i++) {
		if (_parent->dxcc == USEntities[i]) {
			_parent->usa = true;
			break;
		}
	}
	if (!_parent->usa || _parent->callsign.Len() != 3 || FindFocus() == tc_call) {
		_parent->onebyone = false;
	} else {
		// 1x1 callsigns - must have W/K/N as the first character
		// a number as the second and letters A-Z *except* X as
		// the final character
		char first = _parent->callsign[0];
		char second = _parent->callsign[1];
		char third = _parent->callsign[2];
		if (first != 'W' && first != 'K' && first != 'N') {
		valMsg = _("US 1x1 callsigns must start with W, K, or N");
			goto notok;
		}
		if (second < '0' || second > '9') {
			valMsg = _("US 1x1 callsigns must have a number as the second character");
			goto notok;
		}
		if (third < 'A' || third > 'Z' || third == 'X') {
			valMsg = _("US 1x1 callsigns must end in letters A-Z excluding 'X'");
			goto notok;
		}
	}
	// Check for valid 1x1 callsign
	if (_parent->onebyone && !tqsl_isDateValid(&_parent->qsonotafter)) {
		valMsg = _("US 1x1 callsign requests must provide an end date");
		goto notok;
	}

	// Are there any valid certificates for this DXCC entity?
	bool existsValidForEntity;
	existsValidForEntity = false;

	if (!tqsl_selectCertificates(NULL, &ncert, NULL, _parent->dxcc, 0,
				&(_parent->provider), 0)) {
		existsValidForEntity = (ncert > 0);
	}

	// Data looks okay, now let's make sure this isn't a duplicate request
	// (unless it's a renewal).

	if (tqsl_selectCertificates(&certlist, &ncert, _parent->callsign.ToUTF8(), _parent->dxcc, 0,
				&(_parent->provider), 0)) {
		ncert = 0;
	}
	if (!_parent->renewal && ncert > 0) {			// New request, have cert for this callsign
		char cert_before_buf[40], cert_after_buf[40];
		for (int i = 0; i < ncert; i++) {
			// See if this cert overlaps the user-specified date range
			tQSL_Date cert_not_before, cert_not_after;
			int cert_dxcc = 0;
			tqsl_getCertificateQSONotBeforeDate(certlist[i], &cert_not_before);
			tqsl_getCertificateQSONotAfterDate(certlist[i], &cert_not_after);
			tqsl_getCertificateDXCCEntity(certlist[i], &cert_dxcc);
			if (cert_dxcc == _parent->dxcc
					&& ((tqsl_isDateValid(&_parent->qsonotafter)
					&& !(tqsl_compareDates(&_parent->qsonotbefore, &cert_not_after) == 1
					|| tqsl_compareDates(&_parent->qsonotafter, &cert_not_before) == -1))
					|| (!tqsl_isDateValid(&_parent->qsonotafter)
					&& !(tqsl_compareDates(&_parent->qsonotbefore, &cert_not_after) == 1)))) {
				ok = false;	// Overlap!
				tqsl_convertDateToText(&cert_not_before, cert_before_buf, sizeof cert_before_buf);
				tqsl_convertDateToText(&cert_not_after, cert_after_buf, sizeof cert_after_buf);
			}
		}
		tqsl_freeCertificateList(certlist, ncert);
		if (ok == false) {
			DXCC dxcc;
			dxcc.getByEntity(_parent->dxcc);
			// TRANSLATORS: first argument is callsign (%s), second is the related DXCC entity name (%hs)
			valMsg = wxString::Format(_("You have an overlapping Certificate for %s (DXCC=%hs) having QSO dates: "), _parent->callsign.c_str(), dxcc.name());
			// TRANSLATORS: here "to" separates two dates in a date range
			valMsg += wxString::FromUTF8(cert_before_buf) + _(" to ") + wxString::FromUTF8(cert_after_buf);
		}
	}
	{
		wxString pending = wxConfig::Get()->Read(wxT("RequestPending"));
		wxStringTokenizer tkz(pending, wxT(","));
		while (tkz.HasMoreTokens()) {
			wxString pend = tkz.GetNextToken();
			if (pend == _parent->callsign) {
				wxString fmt = _("You have already requested a Callsign Certificate for %s and can not request another until that request has been processed by LoTW Staff.");
					fmt += wxT("\n\n");
					fmt += _("Please wait until you receive an e-mail bearing your requested Callsign Certificate.");
					fmt += wxT("\n\n");
					fmt += _("If you are sure that the earlier request is now invalid you should delete the pending Callsign Certificate for %s.");
				valMsg = wxString::Format(fmt, _parent->callsign.c_str(), _parent->callsign.c_str());
				goto notok;
			}
		}
	}
        {
		wxString requestRecord = wxConfig::Get()->Read(wxT("RequestRecord"));
		wxString requestList;
		wxStringTokenizer rectkz(requestRecord, wxT(","));
		time_t now = time(NULL);
		time_t yesterday = now - 24 * 60 * 60; // 24 hours ago
		int numRequests = 0;
		while (rectkz.HasMoreTokens()) {
			wxString rec = rectkz.GetNextToken();
			char csign[512];
			time_t rectime;
			strncpy(csign, rec.ToUTF8(), sizeof csign);
			char *s = csign;
			while (*s != ':' && *s != '\0')
				s++;
			*s = '\0';
			rectime = strtol(++s, NULL, 10);
			if (rectime < yesterday) continue;		// More than 24 hours old
			if (strcmp(csign, _parent->callsign.ToUTF8()) == 0) { // Same call
				numRequests++;
			}
			if (!requestList.IsEmpty()) {
				requestList = requestList + wxT(",");
			}
			requestList = requestList + wxString::Format(wxT("%hs:%Lu"), csign, rectime);
		}
		wxConfig::Get()->Write(wxT("RequestRecord"), requestList);
		wxConfig::Get()->Flush();

		if (numRequests > 3) {
			wxString fmt = _("You have already requested more than three Callsign Certificates for %s in the past 24 hours. You should submit a request only once, then wait for that request to be processed by LoTW Staff. This may take several business days.");
					fmt += wxT("\n\n");
					fmt += _("Please wait until you receive an e-mail bearing your requested Callsign Certificate.");
					fmt += wxT("\n\n");
			valMsg = wxString::Format(fmt, _parent->callsign.c_str(), _parent->callsign.c_str());
		}
		if (!_parent->renewal && existsValidForEntity) {
			_parent->signIt = CRQ_SIGN_REPLACEMENT;
		}
	}
#endif // DEBUG
notok:
	tc_cs_status->SetLabel(valMsg);
	tc_cs_status->Wrap(_parent->maxWidth);
	return 0;
}

bool
CRQ_CallsignPage::TransferDataFromWindow() {
	tqslTrace("CRQ_CallsignPage::TransferDataFromWindow", NULL);
	bool ok;

	validate();

	bool hasEndDate = (!tqsl_isDateNull(&_parent->qsonotafter) && tqsl_isDateValid(&_parent->qsonotafter));
	bool notInULS = false;

	_parent->signIt = CRQ_SIGN_MAYBE;

	_parent->goodULSData = false;
	// Is this in the ULS?
	if (valMsg.IsEmpty() && _parent->usa && !_parent->onebyone && isUSCallsign(_parent->callsign)) {
		wxString name, attn, addr1, city, state, zip;
		int stat;
		if (_parent->networkError) {
			stat = 3;		// reflect network error
		} else {
			stat = GetULSInfo(_parent->callsign.ToUTF8(), name, attn, addr1, city, state, zip);
		}
		// handle portable/home and home/portable
		if (stat == 2 && _parent->portable && !_parent->networkError) {
			stat = GetULSInfo(_parent->modifier.ToUTF8(), name, attn, addr1, city, state, zip);
		}
		int stat2 = 0;
		switch (stat) {
			case 0:
				_parent->validusa = true;		// Good data returned
				if (name == wxT("null"))
					name = wxT("");
				_parent->name = name;
				_parent->namePage->setName(name);

				if (addr1 == wxT("null"))
					addr1 = _parent->addr1;
				if (attn == wxT("null")) {
					attn = wxT("");
					_parent->addr1 = addr1;
					_parent->addr2 = wxT("");
					_parent->namePage->setAddr1(addr1);
					_parent->namePage->setAddr2(attn);
				} else {
					_parent->addr1 = attn;
					_parent->addr2 = addr1;
					_parent->namePage->setAddr1(attn);
					_parent->namePage->setAddr2(addr1);
				}

				if (city == wxT("null"))
					city = _parent->city;
				_parent->city = city;
				_parent->namePage->setCity(city);

				if (state == wxT("null"))
					state = _parent->state;
				_parent->state = state;
				_parent->namePage->setState(state);

				if (zip == wxT("null"))
					zip = _parent->zip;
				_parent->zip = zip;
				_parent->namePage->setZip(zip);

				_parent->country = wxT("USA");
				_parent->namePage->setCountry(_parent->country);
				if (!_parent->name.IsEmpty() && !_parent->addr1.IsEmpty() && !_parent->city.IsEmpty()) {
					_parent->goodULSData = true;
				}
				break;
			case 1:
				break;						// Error reading ULS info
			case 2:
				stat2 = GetULSInfo("W1AW", name, attn, addr1, city, state, zip);
				if (stat2 == 2)					// Also nothing for a good call
					break;
				if (hasEndDate) {				// Allow former calls
					if (!_parent->validcerts) {
						valMsg = _("You cannot request a Callsign Certificate for a former callsign unless you hold a valid Callsign Certificate to be used to verify that request.");
					}
					notInULS = true;
					break;
				}
				valMsg = wxString::Format(_("The callsign %s is not currently registered in the FCC ULS database.\nIf this is a newly registered call, you must wait at least one business day for it to be valid. Please enter a currently valid callsign."), _parent->callsign.c_str());
				break;
			case 3:
				_parent->networkError = true;			// Error reading
				break;
		}
	}

	// Is this potentially CEPT ?
	if (valMsg.IsEmpty() && _parent->usa && !_parent->modifier.IsEmpty() && !isUSCallsign(_parent->modifier)) {
		wxMessageBox(_("If you are using a US callsign outside of the US persuant to CEPT, IARP or other Reciprocity arrangements, FCC rules require you to be a US Citizen."), _("Warning"), wxOK | wxICON_WARNING, this);
	}
	if (valMsg.IsEmpty()) {
		// If this call has a slash, then it may be a portable call from
		// outside the US. We really can't tell at this point so just
		// let it go.
		if (!_parent->modifier.IsEmpty()) {
			_parent->signIt = CRQ_SIGN_PORTABLE;
		}
		ok = true;
	} else {
		wxMessageBox(valMsg, _("Error"), wxOK | wxICON_ERROR, this);
		ok = false;
	}
	if (ok && _parent->dxcc == 0) {
		if (!_parent->validcerts) {
			wxString msg = _("You cannot select DXCC Entity NONE as you must sign any request for entity NONE and you have no valid Callsign Certificates that you can use to sign this request.");
			wxMessageBox(msg, _("TQSL Error"), wxOK | wxICON_ERROR, this);
			return false;
		}

		_parent->signIt = CRQ_SIGN_NONE;
		wxString msg = _("You have selected DXCC Entity NONE");
			msg += wxT("\n\n");
			msg += _("QSO records signed using the Certificate will not be valid for DXCC award credit (but will be valid for other applicable awards). If the Certificate is to be used for signing QSOs from maritime/marine mobile, shipboard, or air mobile operations, that is the correct selection. Otherwise, you probably should use the \"Back\" button to return to the DXCC page after clicking \"OK\"");
		wxMessageBox(msg, _("TQSL Warning"), wxOK | wxICON_WARNING, this);
	}
	if (ok && _parent->onebyone) {
		if (!_parent->validcerts) {
			wxString msg = _("You cannot request a certificate for a 1x1 callsign as you must sign those requests, but you have no valid Callsign Certificates that you can use to sign this request.");
			wxMessageBox(msg, _("TQSL Error"), wxOK | wxICON_ERROR, this);
			return false;
		}
		_parent->signIt = CRQ_SIGN_1X1;
	}

	if (ok && _parent->signIt == CRQ_SIGN_PORTABLE) {
		if (!_parent->validcerts) {
			wxString msg = _("You cannot request a certificate for a portable callsign as you must sign those requests, but you have no valid Callsign Certificates that you can use to sign this request.");
			wxMessageBox(msg, _("TQSL Error"), wxOK | wxICON_ERROR, this);
			return false;
		}
	}

	if (ok && hasEndDate && !notInULS && !_parent->onebyone) {	// If it has an end date and it's a current call
		wxString msg = _("You have chosen a QSO end date for this Callsign Certificate. The 'QSO end date' should ONLY be set if that date is the date when that callsign's license expired or the license was replaced by a new callsign.");
			msg += wxT("\n\n");
			msg += _("If you set an end date, you will not be able to sign QSOs past that date, even if the Callsign Certificate itself is still valid.");
			msg += wxT("\n\n");
			msg += _("If you still hold this callsign (or if you plan to renew the license for the callsign), you should not set a 'QSO end date'.");
			msg += wxT("\n");
			msg += _("Do you really want to keep this 'QSO end date'?");
		if (wxMessageBox(msg, _("Warning"), wxYES_NO|wxICON_EXCLAMATION, this) == wxNO) {
				tc_qsoendy->SetSelection(0);
				tc_qsoendm->SetSelection(0);
				tc_qsoendd->SetSelection(0);
				return false;
		}
	}
	_parent->callsign = tc_call->GetValue();
	_parent->callsign.MakeUpper();
	tc_call->SetValue(_parent->callsign);
	return ok;
}

static bool
cleanString(wxString &str) {
	str.Trim();
	str.Trim(FALSE);
	return str.IsEmpty();
}

const char *
CRQ_NamePage::validate() {
	tqslTrace("CRQ_NamePage::validate", NULL);
	if (!initialized)
		return 0;
	valMsg = wxT("");
	_parent->name = tc_name->GetValue();
	_parent->addr1 = tc_addr1->GetValue();
	_parent->city = tc_city->GetValue();

	if (cleanString(_parent->name)) {
		valMsg = _("You must enter your name");
	} else if (cleanString(_parent->addr1)) {
		valMsg = _("You must enter your address");
	} else if (cleanString(_parent->city)) {
		valMsg = _("You must enter your city");
	}
	tc_addr_status->SetLabel(valMsg);
	if (!valMsg.IsEmpty()) {
		tc_name->Enable(true);
		tc_addr1->Enable(true);
		tc_addr2->Enable(true);
		tc_city->Enable(true);
		tc_state->Enable(true);
		tc_zip->Enable(true);
		tc_country->Enable(true);
		return 0;
	}
	//
	// If this is not a renewal, and it's in the USA, and there's no certs to sign it with,
	// and we got a valid ULS address, then this is an initial certificate and must match the FCC database. Say so.
	//
	if (_parent->goodULSData && !_parent->renewal && _parent->validusa && !_parent->validcerts) {
		tc_addr_status->SetLabel(_("This address must match the FCC ULS database.\nIf this address information is incorrect, please correct your FCC record."));
		tc_name->Enable(false);
		tc_addr1->Enable(false);
		tc_addr2->Enable(false);
		tc_city->Enable(false);
		tc_state->Enable(false);
		tc_zip->Enable(false);
		tc_country->Enable(false);
	}
	return 0;
}

bool
CRQ_NamePage::TransferDataFromWindow() {
	tqslTrace("CRQ_NamePage::TransferDataFromWindow", NULL);
	_parent->name = tc_name->GetValue();
	_parent->addr1 = tc_addr1->GetValue();
	_parent->addr2 = tc_addr2->GetValue();
	_parent->city = tc_city->GetValue();
	_parent->state = tc_state->GetValue();
	_parent->zip = tc_zip->GetValue();
	_parent->country = tc_country->GetValue();

	bool ok;
	validate();
	if (valMsg.IsEmpty()) {
		ok = true;
	} else {
		wxMessageBox(valMsg, _("Error"), wxOK | wxICON_ERROR, this);
		ok = false;
	}

	cleanString(_parent->name);
	cleanString(_parent->addr1);
	cleanString(_parent->addr2);
	cleanString(_parent->city);
	cleanString(_parent->state);
	cleanString(_parent->zip);
	cleanString(_parent->country);
	tc_name->SetValue(_parent->name);
	tc_addr1->SetValue(_parent->addr1);
	tc_addr2->SetValue(_parent->addr2);
	tc_city->SetValue(_parent->city);
	tc_state->SetValue(_parent->state);
	tc_zip->SetValue(_parent->zip);
	tc_country->SetValue(_parent->country);
	wxConfig *config = reinterpret_cast<wxConfig *>(wxConfig::Get());
	config->Write(wxT("Name"), _parent->name);
	config->Write(wxT("Addr1"), _parent->addr1);
	config->Write(wxT("Addr2"), _parent->addr2);
	config->Write(wxT("City"), _parent->city);
	config->Write(wxT("State"), _parent->state);
	config->Write(wxT("ZIP"), _parent->zip);
	config->Write(wxT("Country"), _parent->country);
	return ok;
}

const char *
CRQ_EmailPage::validate() {
	tqslTrace("CRQ_EmailPage::validate()", NULL);

	if (!initialized)
		return 0;
	valMsg = wxT("");
	_parent->email = tc_email->GetValue();
	cleanString(_parent->email);
	int i = _parent->email.First('@');
	int j = _parent->email.Last('.');
	if (i < 1 || j < i+2 || j == static_cast<int>(_parent->email.length())-1)
		valMsg = _("You must enter a valid email address");
	tc_em_status->SetLabel(valMsg);
	return 0;
}

bool
CRQ_EmailPage::TransferDataFromWindow() {
	tqslTrace("CRQ_EmailPage::TransferDataFromWindow", NULL);
	bool ok;
	validate();
	if (valMsg.IsEmpty()) {
		ok = true;
	} else {
		wxMessageBox(valMsg, _("Error"), wxOK | wxICON_ERROR, this);
		ok = false;
	}

	_parent->email = tc_email->GetValue();
	cleanString(_parent->email);
	wxConfig *config = reinterpret_cast<wxConfig *>(wxConfig::Get());
	config->Write(wxT("Email"), _parent->email);
	return ok;
}

const char *
CRQ_PasswordPage::validate() {
	tqslTrace("CRQ_PasswordPage::validate", NULL);

	if (!initialized)
		return 0;
	valMsg = wxT("");
	wxString pw1 = tc_pw1->GetValue();
	wxString pw2 = tc_pw2->GetValue();

	if (pw1 != pw2)
		valMsg = _("The two copies of the passphrase do not match.");
	tc_pwd_status->SetLabel(valMsg);
	return 0;
}

bool
CRQ_PasswordPage::TransferDataFromWindow() {
	tqslTrace("CRQ_PasswordPage::TransferDataFromWindow", NULL);
	bool ok;
	validate();
	if (valMsg.IsEmpty()) {
		ok = true;
	} else {
		wxMessageBox(valMsg, _("Error"), wxOK | wxICON_ERROR, this);
		ok = false;
	}
	_parent->password = tc_pw1->GetValue();
	return ok;
}

void
CRQ_SignPage::OnPageChanging(wxWizardEvent& ev) {
	tqslTrace("CRQ_SignPage::OnPageChanging", "Direction=", ev.GetDirection());

	validate();
	if (!valMsg.IsEmpty() && ev.GetDirection()) {
		ev.Veto();
		wxMessageBox(valMsg, _("TQSL Error"), wxOK | wxICON_ERROR, this);
	}
}


const char *
CRQ_SignPage::validate() {
	tqslTrace("CRQ_SignPage::validate", NULL);
	bool error = false;

	if (!initialized)
		return 0;

	valMsg = wxT("");
	wxString nextprompt = _("Click 'Finish' to complete this Callsign Certificate request.");

	bool doSigned = _parent->ShouldBeSigned();
	cert_tree->Show(doSigned);

	if (!_parent->MustBeSigned()) {
		nextprompt = _("Please select a Callsign Certificate for the account where you would like the QSOs to be stored");
	} else {
		if (_parent->signIt == CRQ_SIGN_REPLACEMENT) {
			valMsg = _("Please select the Callsign Certificate for your current personal callsign to validate your request.");
		} else {
			valMsg = _("Please select a Callsign Certificate to validate this request");
		}
		if (!cert_tree->GetSelection().IsOk() || cert_tree->GetItemData(cert_tree->GetSelection()) == NULL) {
			error = true;
			if (_parent->signIt == CRQ_SIGN_REPLACEMENT) {
				valMsg = _("Please select the Callsign Certificate for your current personal callsign to validate your request.");
			} else {
				valMsg = _("Please select a Callsign Certificate to validate this request");
			}
		} else {
			char callsign[512];
			tQSL_Cert cert = cert_tree->GetItemData(cert_tree->GetSelection())->getCert();
			if (0 == tqsl_getCertificateCallSign(cert, callsign, sizeof callsign)) {
				wxString fmt = wxT("\n\n");
					fmt += _("QSOs for %hs will be stored in the LoTW account for %s.");
				nextprompt+=wxString::Format(fmt, _parent->callsign.c_str(), callsign);
			}
		}
	}

	tc_sign_status->SetLabel(error ? valMsg : nextprompt);
	tc_sign_status->Wrap(_parent->maxWidth);
	return 0;
}

bool
CRQ_SignPage::TransferDataFromWindow() {
	tqslTrace("CRQ_SignPage::TransferDataFromWindow", NULL);
	validate();

	_parent->cert = 0;
	CertTreeItemData *data = reinterpret_cast<CertTreeItemData *>(cert_tree->GetItemData(cert_tree->GetSelection()));
	if (data)
		_parent->cert = data->getCert();
	return true;
}

