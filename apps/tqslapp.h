/***************************************************************************
                          tqslapp.h  -  description
                             -------------------
    begin                : Sun Jun 16 2002
    copyright            : (C) 2002 by ARRL
    author               : Jon Bloom
    email                : jbloom@arrl.org
    revision             : $Id$
 ***************************************************************************/

#ifndef __tqslapp_h
#define __tqslapp_h

#define TQSL_CRQ_FILE_EXT "tq5"
#define TQSL_CERT_FILE_EXT "tq6"

#ifdef __WXMSW__
	#define ALLFILESWILD "*.*"
#else
	#define ALLFILESWILD "*"
#endif

#define MAIN_WINDOW_MIN_HEIGHT 400
#define MAIN_WINDOW_MIN_WIDTH  575

#include "tqslconvert.h"
#include "qsodatadialog.h"
#include "certtree.h"
#include "loctree.h"
#include "wxutil.h"

enum {
	tm_f_import = 7000,
	tm_f_import_compress,
	tm_f_test_signing,
	tm_f_upload,
	tm_f_compress,
	tm_f_uncompress,
	tm_f_preferences,
	tm_f_loadconfig,
	tm_f_saveconfig,
	tm_f_new,
	tm_f_edit,
	tm_f_diag,
	tm_f_exit,
	tm_f_lang,
	tm_s_add,
	tm_s_edit,
	tm_s_undelete,
	tm_h_contents,
	tm_h_about,
	tm_h_update,
	tm_h_sync,
	bg_updateCheck,
	bg_expiring,
	tmr_db
};

// Action values
enum {
	TQSL_ACTION_ASK = 0,
	TQSL_ACTION_ABORT = 1,
	TQSL_ACTION_NEW = 2,
	TQSL_ACTION_ALL = 3,
	TQSL_ACTION_UNSPEC = 4
};

#define TQSL_LOG_TAB 3

#define TQSL_CD_MSG TQSL_ID_LOW
#define TQSL_CD_CANBUT TQSL_ID_LOW+1
#define TQSL_DB_CANBUT TQSL_ID_LOW+2

#define CERTLIST_FLAGS TQSL_SELECT_CERT_WITHKEYS | TQSL_SELECT_CERT_SUPERCEDED | TQSL_SELECT_CERT_EXPIRED
// Exit codes
enum {
	TQSL_EXIT_SUCCESS = 0,
	TQSL_EXIT_CANCEL = 1,
	TQSL_EXIT_REJECTED = 2,
	TQSL_EXIT_UNEXP_RESP = 3,
	TQSL_EXIT_TQSL_ERROR = 4,
	TQSL_EXIT_LIB_ERROR = 5,
	TQSL_EXIT_ERR_OPEN_INPUT = 6,
	TQSL_EXIT_ERR_OPEN_OUTPUT = 7,
	TQSL_EXIT_NO_QSOS = 8,
	TQSL_EXIT_QSOS_SUPPRESSED = 9,
	TQSL_EXIT_COMMAND_ERROR = 10,
	TQSL_EXIT_CONNECTION_FAILED = 11,
	TQSL_EXIT_UNKNOWN = 12,
	TQSL_EXIT_BUSY = 13,
	TQSL_EXIT_UPLOADED_ALREADY = 14,
	TQSL_EXIT_BAD_PASSPHRASE = 15
};

// types of signed log files
enum {
	TQSL_UNCOMPRESSED_FILE,
	TQSL_COMPRESSED_FILE,
	TQSL_TEST_SIGNING
};

// Sign type
enum {
	TQSL_SIGN_LOG = 0,	// Normal signing
	TQSL_TEST_LOG = 1,	// Test log only
	TQSL_UPLOAD_ONLY = 2	// Populate upload database only
};

bool tqsl_checkCertStatus(long serial, wxString& result);

class MyFrame : public wxFrame {
 public:
	MyFrame(const wxString& title, int x, int y, int w, int h, bool checkUpdates, bool quiet, wxLocale* locale);

	bool IsQuiet(void) { return _quiet; }
	void AddStationLocation(wxCommandEvent& event);
	void EditStationLocation(wxCommandEvent& event);
	void EnterQSOData(wxCommandEvent& event);
	void EditQSOData(wxCommandEvent& event);
	void ProcessQSODataFile(bool upload, int compressed);
	void ImportQSODataFile(wxCommandEvent& event);
	void TestSignQSODataFile(wxCommandEvent& event);
	void UploadQSODataFile(wxCommandEvent& event);
	void SaveWindowLayout(void);
	void OnExit(TQ_WXCLOSEEVENT& event);
	void DoExit(wxCommandEvent& event);
	void DoUpdateCheck(bool silent, bool noGUI);
	void OnUpdateCheckDone(wxCommandEvent& event);
	void OnHelpAbout(wxCommandEvent& event);
	void OnHelpContents(wxCommandEvent& event);
	void OnHelpDiagnose(wxCommandEvent& event);
#ifdef ALLOW_UNCOMPRESSED
	void OnFileCompress(wxCommandEvent& event);
#endif
	void OnPreferences(wxCommandEvent& event);
	void OnSaveConfig(wxCommandEvent& event);
	void DoRestoreConfig(wxString& filename);
	void OnLoadConfig(wxCommandEvent& event);
	void LoadDupes(void);
	int ConvertLogFile(tQSL_Location loc, const wxString& infile, const wxString& outfile, int compress = TQSL_UNCOMPRESSED_FILE, bool suppressdate = false, tQSL_Date* startdate = NULL, tQSL_Date* enddate = NULL, int action = TQSL_ACTION_ASK, int logverify = -1, const char *password = NULL, const char *defcall = NULL);
	tQSL_Location SelectStationLocation(const wxString& title = wxT(""), const wxString& okLabel = _("OK"), bool editonly = false);
	int ConvertLogToString(tQSL_Location loc, const wxString& infile, wxString& output, int& n, bool suppressdate = false, tQSL_Date* startdate = NULL, tQSL_Date* enddate = NULL, int action = TQSL_ACTION_ASK, int logverify = -1, const char* password = NULL, const char* defcall = NULL, int signtype = TQSL_SIGN_LOG);
	int UploadLogFile(tQSL_Location loc, const wxString& infile, bool compress = false, bool suppressdate = false, tQSL_Date* startdate = NULL, tQSL_Date* enddate = NULL, int action = TQSL_ACTION_ASK, int logverify = -1, const char* password = NULL, const char *defcall = NULL);
	int UploadFile(const wxString& infile, const char* filename, int numrecs, void *content, size_t clen, const wxString& fileType);

	void CheckForUpdates(wxCommandEvent&);
	void DoCheckForUpdates(bool quiet = false, bool noGUI = false);
	void UpdateConfigFile(void);
#if defined(_WIN32) || defined(__APPLE__)
	void UpdateTQSL(wxString& url);
#endif
	void DoLoTWSync(wxCommandEvent&);
	void DoCheckExpiringCerts(bool noGUI = false);
	void OnExpiredCertFound(wxCommandEvent& event);

	void OnQuit(wxCommandEvent& event);
	void CRQWizard(wxCommandEvent& event);
	void CRQWizardRenew(wxCommandEvent& event);
	void OnCertTreeSel(wxTreeEvent& event);
	void CertTreeReset(void);
	void OnCertProperties(wxCommandEvent& event);
	void OnCertExport(wxCommandEvent& event);
	void OnCertDelete(wxCommandEvent& event);
	void OnCertUndelete(wxCommandEvent& event);
//	void OnCertImport(wxCommandEvent& event);
	void OnSign(wxCommandEvent& event);
	void OnLoadCertificateFile(wxCommandEvent& event);
	void OnLocProperties(wxCommandEvent& event);
	void OnLocDelete(wxCommandEvent& event);
	void OnLocUndelete(wxCommandEvent& event);
	void OnLocEdit(wxCommandEvent& event);
	void OnLocTreeSel(wxTreeEvent& event);
	void OnLoginToLogbook(wxCommandEvent& event);
	void OnChooseLanguage(wxCommandEvent& event);
	void LocTreeReset(void);
	void DisplayHelp(const char *file = "main.htm") { help->Display(wxString::FromUTF8(file)); }
	void FirstTime(void);
	void BackupConfig(const wxString& event, bool quiet);
	void AutoBackup(void);
	void SaveOldBackups(const wxString& directory, const wxString& filename, const wxString& ext);

	CertTree *cert_tree;
	LocTree *loc_tree;
	wxTextCtrl *logwin;
	wxNotebook *notebook;
	wxHtmlHelpController *help;
	wxMenu* file_menu;
	wxMenu *cert_menu;
	wxMenu* help_menu;
	tQSL_Converter logConv;

	DECLARE_EVENT_TABLE()

	wxLocale* locale;

 private:
	wxBitmapButton* loc_add_button;
	wxStaticText* loc_add_label;
	wxBitmapButton* loc_edit_button;
	wxStaticText* loc_edit_label;
	wxBitmapButton* loc_delete_button;
	wxStaticText* loc_delete_label;
	wxBitmapButton* cert_load_button;
	wxStaticText* cert_load_label;
	wxBitmapButton* cert_save_button;
	wxStaticText* cert_save_label;
	wxBitmapButton* cert_renew_button;
	wxStaticText* cert_renew_label;
	wxStaticText* loc_select_label;
	wxStaticText* cert_select_label;
	wxBitmapButton* cert_prop_button;
	wxStaticText* cert_prop_label;
	wxBitmapButton* loc_prop_button;
	wxStaticText* loc_prop_label;
	int renew;
	TQSL_CERT_REQ *req;
	bool _quiet;
};

int SaveAddressInfo(const char *callsign, int dxcc);

class LocPropDial : public wxDialog {
 public:
        explicit LocPropDial(wxString locname, bool display, const char *filename = NULL, wxWindow *parent = 0);
        void closeMe(wxCommandEvent&) { EndModal(wxID_OK); }
        DECLARE_EVENT_TABLE()
};

#endif // __tqslapp_h
