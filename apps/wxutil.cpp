/***************************************************************************

	                       wxutil.cpp  -  description
	                          -------------------
	 begin                : Thu Aug 14 2003
	 copyright            : (C) 2003 by ARRL
	 author               : Jon Bloom
	 email                : jbloom@arrl.org
	 revision             : $Id$
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "sysconfig.h"
#endif

#include "wxutil.h"
#include <wx/dir.h>
#include <wx/config.h>
#include <wx/filename.h>
#include <wx/treectrl.h>
#include <wx/textctrl.h>
#include "tqsllib.h"
#include "tqslerrno.h"
#include <vector>

#if wxMAJOR_VERSION == 3 && wxMINOR_VERSION > 0
#define WX31		// wxWidgets isn't done until stuff doesn't run
#endif

wxSize
getTextSize(wxWindow *win) {
	wxClientDC dc(win);
	wxCoord char_width, char_height;
	dc.GetTextExtent(wxString(wxT("M")), &char_width, &char_height);
	return wxSize(char_width, char_height);
}

// isspace() called on extended chars in UTF-8 raises asserts in
// the windows C++ libs. Don't call isspace() if out of range.

static inline int isspc(int c) {
	if (c < 0 || c > 255)
		return 0;
	return isspace(c);
}

wxString
wrapString(wxWindow *win, wxString in, int length) {
	wxClientDC dc(win);
	wxCoord textwidth, textheight;
	wxString out = wxT("");
	wxString str = in;
	do {
		dc.GetTextExtent(str, &textwidth, &textheight);
		if (textwidth > length) {
			int index = 0;
				do {
					str = str.Left(str.Length()-1);
					index++;
					dc.GetTextExtent(str, &textwidth, &textheight);

					wxString c = wxString(str.Last());

					if (textwidth < length && isspc(c[0]))
						break;
				} while (1);
			if (!out.IsEmpty())
				out += wxT("\n");
			out += str;
			str = in.Right(index);
		} else {
			break;
		}
	} while (1);
	if (!out.IsEmpty())
		out += wxT("\n");
	out += str;
	return out;
}

// Strip special characters from a string prior to writing to XML
wxString
urlEncode(wxString& str) {
	str.Replace(wxT("&"), wxT("&amp;"), true);
	str.Replace(wxT("\""), wxT("&quot;"), true);
	str.Replace(wxT("'"), wxT("&apos;"), true);
	str.Replace(wxT("<"), wxT("&lt;"), true);
	str.Replace(wxT(">"), wxT("&gt;"), true);
	return str;
}

// Convert UTF-8 string to UCS-2 (MS Unicode default)
int
utf8_to_ucs2(const char *in, char *out, size_t buflen) {
	size_t len = 0;

	while (len < buflen) {
		if ((unsigned char)*in < 0x80) {		// ASCII range
			*out++ = *in;
			if (*in++ == '\0')			// End of string
				break;
			len++;
		} else if (((unsigned char)*in & 0xc0) == 0xc0) {  // Two-byte
			*out++ = ((in[0] & 0x1f) << 6) | (in[1] & 0x3f);
			in += 2;
			len++;
		} else if (((unsigned char)*in & 0xe0) == 0xe0) {  // Three-byte
			unsigned short three =	((in[0] & 0x0f) << 12) |
						 ((in[1] & 0x3f) << 6) |
						 (in[2] & 0x3f);
			*out++ = (three & 0xff00) >> 8;
			len++;
			if (len < buflen) {
				*out++ = (three & 0xff);
				len++;
			}
			in += 3;
		} else {
			in++;		// Unknown. Skip input.
		}
	}
	out[len-1] = '\0';
	return len;
}
int
getPasswordFromUser(wxString& result, const wxString& message, const wxString& caption, const wxString& defaultValue, wxWindow *parent) {
	long style = wxTextEntryDialogStyle;

	wxPasswordEntryDialog dialog(parent, message, caption, defaultValue, style);

	int ret = dialog.ShowModal();
	if (ret == wxID_OK)
		result = dialog.GetValue();

	return ret;
}

static const char *error_strings[] = {
	__("Memory allocation failure"),			/* TQSL_ALLOC_ERROR */
	__("Unable to initialize random number generator"),	/* TQSL_RANDOM_ERROR */
	__("Invalid argument"),					/* TQSL_ARGUMENT_ERROR */
	__("Operator aborted operation"),			/* TQSL_OPERATOR_ABORT */
	__("No Certificate Request matches the selected Callsign Certificate"),/* TQSL_NOKEY_ERROR */
	__("Buffer too small"),					/* TQSL_BUFFER_ERROR */
	__("Invalid date format"),				/* TQSL_INVALID_DATE */
	__("Certificate not initialized for signing"),		/* TQSL_SIGNINIT_ERROR */
	__("Passphrase not correct"),				/* TQSL_PASSWORD_ERROR */
	__("Expected name"),					/* TQSL_EXPECTED_NAME */
	__("Name exists"),					/* TQSL_NAME_EXISTS */
	__("Data for this DXCC entity could not be found"),	/* TQSL_NAME_NOT_FOUND */
	__("Invalid time format"),				/* TQSL_INVALID_TIME */
	__("QSO date is not within the date range specified on your Callsign Certificate"),	/* TQSL_CERT_DATE_MISMATCH */
	__("Certificate provider not found"),			/* TQSL_PROVIDER_NOT_FOUND */
	__("No callsign certificate for key"),			/* TQSL_CERT_KEY_ONLY */
	__("Configuration file cannot be opened"),		/* TQSL_CONFIG_ERROR */
	__("The private key for this Callsign Certificate is not present on this computer; you can obtain it by loading a .tbk or .p12 file"),				      /* TQSL_CERT_NOT_FOUND */
	__("PKCS#12 file not TQSL compatible"),			/* TQSL_PKCS12_ERROR */
	__("Callsign Certificate not TQSL compatible"),		/* TQSL_CERT_TYPE_ERROR */
	__("Date out of range"),				/* TQSL_DATE_OUT_OF_RANGE */
	__("Already Uploaded QSO detected"),			/* TQSL_DUPLICATE_QSO */
	__("Database error"),					/* TQSL_DB_ERROR */
	__("The selected station location could not be found"),	/* TQSL_LOCATION_NOT_FOUND */
	__("The selected callsign could not be found"),		/* TQSL_CALL_NOT_FOUND */
	__("The TQSL configuration file cannot be parsed"),	/* TQSL_CONFIG_SYNTAX_ERROR */
	__("This file can not be processed due to a system error"),	/* TQSL_FILE_SYSTEM_ERROR */
	__("The format of this file is incorrect."),		/* TQSL_FILE_SYNTAX_ERROR */
	__("Callsign certificate could not be installed"),	/* TQSL_CERT_ERROR */
	__("Callsign Certificate does not match QSO details"),	/* TQSL_CERT_MISMATCH */
	__("Station Location does not match QSO details"),	/* TQSL_LOCATION_MISMATCH */
	__("This Callsign Certificate cannot be installed as the first date where it is valid is in the future. Check if your computer is set to the proper date.\n\n"),
        __("This Callsign Certificate cannot be installed as it has expired. Check if your computer is set to the proper date and that this is the latest Callsign Certificate.\n\n"),
};

static wxString
getLocalizedErrorString_v(int err) {
	int adjusted_err;
	wxString buf;

	if (err == 0)
		return _("NO ERROR");
	if (err == TQSL_CUSTOM_ERROR) {
		if (tQSL_CustomError[0] == 0) {
			return _("Unknown custom error");
		} else {
			return wxString::FromUTF8(tQSL_CustomError);
		}
	}
	if (err == TQSL_DB_ERROR) {
		if (!strcmp(tQSL_CustomError, "dblocked")) {
			return _("TQSL is unable to sign QSOs because another instance of TQSL is busy.\nTerminate any other copies of TQSL and try again.");
		} else if (tQSL_CustomError[0] != 0) {
			return wxString::Format(_("Database Error: %hs"), tQSL_CustomError);
		} else {
			return _("Uploads database error");
		}
	}

	if (err == TQSL_SYSTEM_ERROR || err == TQSL_FILE_SYSTEM_ERROR) {
		if (strlen(tQSL_ErrorFile) > 0) {
			buf = wxString::Format(_("System error: %hs : %hs"),
				tQSL_ErrorFile, strerror(tQSL_Errno));
			tQSL_ErrorFile[0] = '\0';
		} else {
			buf = wxString::Format(_("System error: %hs"),
				strerror(tQSL_Errno));
		}
		return buf;
	}
	if (err == TQSL_FILE_SYNTAX_ERROR) {
		tqslTrace("SyntaxError", "File (partial) content '%s'", tQSL_CustomError);
		if (strlen(tQSL_ErrorFile) > 0) {
			buf = wxString::Format(_("File syntax error: %hs"),
				tQSL_ErrorFile);
			tQSL_ErrorFile[0] = '\0';
		} else {
			buf = _("File syntax error");
		}
		return buf;
	}
	if (err == TQSL_OPENSSL_ERROR) {
		// Get error details from tqsllib as we have
		// no visibility into the tqsllib openssl context
		const char *msg = tqsl_getErrorString();
		return wxString::FromUTF8(msg);
	}
	if (err == TQSL_ADIF_ERROR) {
		if (strlen(tQSL_ErrorFile) > 0) {
			buf = wxString::Format(wxT("%hs: %hs"), tQSL_ErrorFile, tqsl_adifGetError(tQSL_ADIF_Error));
			tQSL_ErrorFile[0] = '\0';
		} else {
			buf = wxString::FromUTF8(tqsl_adifGetError(tQSL_ADIF_Error));
		}
		return buf;
	}
	if (err == TQSL_CABRILLO_ERROR) {
		if (strlen(tQSL_ErrorFile) > 0) {
			buf = wxString::Format(wxT("%hs: %hs"),
				tQSL_ErrorFile, tqsl_cabrilloGetError(tQSL_Cabrillo_Error));
			tQSL_ErrorFile[0] = '\0';
		} else {
			buf = wxString::FromUTF8(tqsl_cabrilloGetError(tQSL_Cabrillo_Error));
		}
		return buf;
	}
	if (err == TQSL_OPENSSL_VERSION_ERROR) {
		// No visibility into the tqsllib openssl context
		const char *msg = tqsl_getErrorString();
		return wxString::FromUTF8(msg);
	}
	if (err == TQSL_CERT_NOT_FOUND && tQSL_ImportCall[0] != '\0') {
		return wxString::Format(
			_("The private key for callsign %hs serial %ld is not present on this computer; you can obtain it by loading a .tbk or .p12 file"),
			tQSL_ImportCall, tQSL_ImportSerial);
	}
	adjusted_err = (err - TQSL_ERROR_ENUM_BASE) & ~0x1000;
	if (adjusted_err < 0 ||
		adjusted_err >=
		static_cast<int>(sizeof error_strings / sizeof error_strings[0])) {
		return wxString::Format(_("Invalid error code: %d"), err);
	}

	if (err == TQSL_CERT_MISMATCH || err == TQSL_LOCATION_MISMATCH) {
		const char *fld, *cert, *qso;
		fld = strtok(tQSL_CustomError, "|");
		cert = strtok(NULL, "|");
		qso = strtok(NULL, "|");
		if (qso == NULL) {		// Nothing in the cert
			qso = cert;
			cert = "none";
		}
		wxString tp(_("Callsign Certificate"));
		if (err == TQSL_LOCATION_MISMATCH)
			tp = wxString(_("Station Location"));
	 	wxString composed = wxGetTranslation(wxString::FromUTF8(error_strings[adjusted_err]));
		// TRANSLATORS: This message is for QSO details. For example, 'The Station Location GRIDSQUARE has value FM18ju while QSO has FM18jt'
		composed = composed + wxT("\n") + wxString::Format(_("The %s '%hs' has value '%hs' while QSO has '%hs'"), tp.c_str(), fld, cert, qso);
		return composed;
	}
	if (err == (TQSL_LOCATION_MISMATCH | 0x1000)) {
		const char *fld, *val;
		fld = strtok(tQSL_CustomError, "|");
		val = strtok(NULL, "|");
	 	wxString composed(_("This log has invalid QSO information"));
		// TRANSLATORS: This message is for QSO details. For example, 'The log being signed has 'US County' set to Foobar which is not valid'
		composed = composed + wxT("\n") + wxString::Format(_("The log being signed has '%hs' set to value '%hs' which is not valid"), fld, val);
		return composed;
	}
	if (err == (TQSL_CERT_NOT_FOUND | 0x1000)) {
		err = TQSL_CERT_NOT_FOUND;
		const char *call, *ent;
		call = strtok(tQSL_CustomError, "|");
		ent = strtok(NULL, "|");
		wxString composed = wxString::Format(_("There is no valid callsign certificate for %hs in entity %hs available. This QSO cannot be signed"), call, ent);
		return composed;
	}
	return wxGetTranslation(wxString::FromUTF8(error_strings[adjusted_err]));
}

wxString
getLocalizedErrorString() {
	wxString cp = getLocalizedErrorString_v(tQSL_Error);
	tQSL_Error = TQSL_NO_ERROR;
	tQSL_Errno = 0;
	tQSL_ErrorFile[0] = 0;
	tQSL_CustomError[0] = 0;
	return cp;
}
/*
 * wxWidgets used to keep language IDs stable, by adding to the end of the
 * enum. wx3 seems to have broken that promise by injecting several languages
 * in the middle. But we use language IDs to specify the local language. Horrid.
 * So, map from old to new. Unfortunately, these aren't stable so adding new
 * languages means editing this.
 */

wxLanguage langWX2toWX3(wxLanguage wx2) {
#if wxMAJOR_VERSION > 2
	switch (wx2) {
		case 42:
			return wxLANGUAGE_CATALAN;
		case 43: // Map wxLANGUAGE_CHINESE to SIMPLIFIED
		case 44:
			return wxLANGUAGE_CHINESE_SIMPLIFIED;
		case 45:
			return wxLANGUAGE_CHINESE_TRADITIONAL;
		case 56:
			return wxLANGUAGE_ENGLISH;
		case 77:
			return wxLANGUAGE_FINNISH;
		case 78:
			return wxLANGUAGE_FRENCH;
		case 87:
			return wxLANGUAGE_GERMAN;
		case 99:
			return wxLANGUAGE_HINDI;
		case 108:
			return wxLANGUAGE_ITALIAN;
		case 110:
			return wxLANGUAGE_JAPANESE;
		case 149:
			return wxLANGUAGE_POLISH;
		case 150:
			return wxLANGUAGE_PORTUGUESE;
		case 156:
			return wxLANGUAGE_RUSSIAN;
		case 175:
			return wxLANGUAGE_SPANISH;
		case 198:
			return wxLANGUAGE_SWEDISH;
		case 210:
			return wxLANGUAGE_TURKISH;
		default:
			return wx2;
	}
#endif
	return wx2;
}

#if (wxUSE_ACCESSIBILITY && defined(__WXMAC__))
#if wxMAJOR_VERSION < 3
#define nullptr NULL
#endif

WindowAccessible::WindowAccessible(wxWindow* win) : wxAccessible(win) {
	// - already being done - if (win) win->SetAccessible(this);
}

wxAccStatus WindowAccessible::GetName(int childId, wxString* name) {
	wxCHECK(GetWindow() != nullptr, wxACC_FAIL);

	name->Clear();
	// If the control has children, don't override their names
	if (childId > 0)
		return wxACC_NOT_IMPLEMENTED;
	*name = GetWindow()->GetName();
	return wxACC_OK;
}

#if (wxMAJOR_VERSION < 3)

// Just an alias
#define TreeCtrlAx WindowAccessible
#define ComboBoxAx WindowAccessible
#define ButtonAx WindowAccessible

#else  // Mac and wx3+
// utility functions
namespace {
enum treeNodeType {
	RootNode,
	ParentNode,
	LeafNode
};
class treeInfo {
 public:
	treeInfo(treeNodeType nt, int position, wxTreeItemId id, wxString name) : _nt(nt), _position(position), _id(id), _name(name) {}
	treeNodeType _nt;
	int _position;
	wxTreeItemId _id;
	wxString _name;
};
static std::vector <treeInfo> tree;

static void AddKids(const wxTreeCtrl* ctrl, wxTreeItemId parent, wxString parentName) {
	wxTreeItemIdValue cookie;
	wxString name;
	wxTreeItemId kid = ctrl->GetFirstChild(parent, cookie);
	while (kid.IsOk()) {
		wxTreeItemId inner = kid;
		while(inner.IsOk()) {
			// Walk the siblings below the root
			treeNodeType nt = LeafNode;
			if (ctrl->GetChildrenCount(inner))
				nt = ParentNode;
			name = ctrl->GetItemText(inner);
			if (!parentName.IsEmpty()) {
				name = parentName + wxT(" : ") + name;
			}
			tree.push_back(treeInfo(nt, tree.size(), inner, name));
			if (nt == ParentNode) {
				AddKids(ctrl, inner, name);
			}
			inner = ctrl->GetNextSibling(inner);
		}
		kid = ctrl->GetNextChild(kid, cookie);
	}
}

static void LoadTreeInfo(const wxTreeCtrl* ctrl) {
	tree.clear();
	wxTreeItemId item = ctrl->GetRootItem();
	wxString name = ctrl->GetName();
	tree.push_back(treeInfo(RootNode, tree.size(), item, name));
	wxTreeItemIdValue cookie;
	wxTreeItemId childId = ctrl->GetFirstChild(item, cookie);
	if (childId.IsOk()) {
		wxTreeItemId inner = childId;
		while(inner.IsOk()) {
			// Walk the siblings below the root
			treeNodeType nt = LeafNode;
			if (ctrl->GetChildrenCount(inner)) {
				nt = ParentNode;
			}
			name = ctrl->GetItemText(inner);
			tree.push_back(treeInfo(nt, tree.size(), inner, name));
			if (nt == ParentNode) {
				AddKids(ctrl, inner, name);
			}
			inner = ctrl->GetNextSibling(inner);
		}
	}
}

unsigned FindItemPosition(const wxTreeCtrl *ctrl, wxTreeItemId id) {
	// Return the 1-based count of the item's position in the pre-order
	// visit of the items in the tree (not counting the root item which we
	// assume is a dummy that never matches id)
	LoadTreeInfo(ctrl);
	for (int position = 0; position < tree.size(); position++) {
		if (tree[position]._id == id)
			return position;
	}
	return 0;
}

wxTreeItemId FindItem(const wxTreeCtrl *ctrl, int nn) {
	// The inverse of the function above
	LoadTreeInfo(ctrl);
	if (nn < 0 || nn >= tree.size())
		return 0;
	return tree[nn]._id;
}
} // namespace

TreeCtrlAx::TreeCtrlAx(wxTreeCtrl *ctrl) : WindowAccessible(ctrl) {
}

TreeCtrlAx::~TreeCtrlAx() {}

wxAccStatus TreeCtrlAx::GetChild(int childId, wxAccessible** child) {
	if (childId == wxACC_SELF) {
		*child =  this;
	} else {
		*child = NULL;
	}
	return wxACC_OK;
}

wxAccStatus TreeCtrlAx::GetChildCount(int* childCount) {
	wxCHECK(GetWindow() != nullptr, wxACC_FAIL);
	wxTreeCtrl* ctrl = GetCtrl();
	if (!ctrl)
		return wxACC_FAIL;

	*childCount = ctrl->GetCount();
	return wxACC_OK;
}

wxAccStatus TreeCtrlAx::GetDefaultAction(int WXUNUSED(childId), wxString* actionName) {
	actionName->clear();

	return wxACC_OK;
}

// Returns the description for this object or a child.
wxAccStatus TreeCtrlAx::GetDescription(int childId, wxString *description) {
	if (childId == wxACC_SELF) {
		*description = _("Tree Ctrl - use control/option/arrow keys to navigate");
	} else {
		description->Clear();
	}
	return wxACC_OK;
}

// This isn't really used yet by wxWidgets as patched by Audacity for
// Mac accessibility, as of Audacity 2.3.2, but here it is anyway, keeping the
// analogy with TrackPanelAx
wxAccStatus TreeCtrlAx::GetFocus(int *childId, wxAccessible **child) {
	wxCHECK(GetWindow() != nullptr, wxACC_FAIL);
	wxTreeCtrl* ctrl = GetCtrl();
	if (!ctrl)
		return wxACC_FAIL;

	wxTreeItemId item = ctrl->GetFocusedItem();
	int id = FindItemPosition(ctrl, item);
	*childId = id;
	*child = nullptr;
	return wxACC_OK;
}

// Returns help text for this object or a child, similar to tooltip text.
wxAccStatus TreeCtrlAx::GetHelpText(int WXUNUSED(childId), wxString *helpText) {
	wxCHECK(GetWindow() != nullptr, wxACC_FAIL);
	helpText->clear();

	return wxACC_OK;
}

// Returns the keyboard shortcut for this object or child.
// Return e.g. ALT+K
wxAccStatus TreeCtrlAx::GetKeyboardShortcut(int WXUNUSED(childId), wxString *shortcut) {
	wxCHECK(GetWindow() != nullptr, wxACC_FAIL);
	shortcut->clear();

	return wxACC_OK;
}

wxAccStatus TreeCtrlAx::GetLocation(wxRect& rect, int elementId) {
	wxCHECK(GetWindow() != nullptr, wxACC_FAIL);
	wxTreeCtrl *ctrl = GetCtrl();
	if (!ctrl)
		return wxACC_FAIL;

	if (elementId == wxACC_SELF) {
		rect = ctrl->GetRect();
	} else {
		wxTreeItemId item = FindItem(ctrl, elementId);
      		if (!(item && ctrl->GetBoundingRect(item, rect))) {
#ifdef wxACC_INVALID_ARG
			return wxACC_INVALID_ARG;
#else
			return wxACC_FAIL;
#endif
		}
	}
	rect.SetPosition(ctrl->GetParent()->ClientToScreen(rect.GetPosition()));
	return wxACC_OK;
}

wxAccStatus TreeCtrlAx::GetName(int childId, wxString* name) {
	wxCHECK(GetWindow() != nullptr, wxACC_FAIL);
	if (childId == wxACC_SELF) {
		return WindowAccessible::GetName(childId, name);
	} else {
		wxTreeCtrl* ctrl = GetCtrl();
		if (!ctrl) {
			return wxACC_FAIL;
		}
		wxTreeItemId item = FindItem(ctrl, childId);
		if (item) {
			*name = tree[childId]._name;
			return wxACC_OK;
		} else {
#ifdef wxACC_INVALID_ARG
			return wxACC_INVALID_ARG;
#else
			return wxACC_FAIL;
#endif
		}
	}
}

wxAccStatus TreeCtrlAx::GetRole(int childId, wxAccRole* role) {
	// Not sure if this correct, but it is analogous with what we use in
	// TrackPanel

	*role = childId == wxACC_SELF ? wxROLE_SYSTEM_PANE : wxROLE_SYSTEM_STATICTEXT;
	return wxACC_OK;
}

// Returns a state constant.
wxAccStatus TreeCtrlAx::GetState(int childId, long* state) {
	wxCHECK(GetWindow() != nullptr, wxACC_FAIL);
	wxTreeCtrl* ctrl = GetCtrl();
	if (!ctrl)
		return wxACC_FAIL;

	*state =  wxACC_STATE_SYSTEM_FOCUSABLE | wxACC_STATE_SYSTEM_SELECTABLE;

	if (childId == wxACC_SELF) {
		if (ctrl->IsExpanded(ctrl->GetRootItem())) {
			*state |= wxACC_STATE_SYSTEM_EXPANDED;
		} else {
			*state |= wxACC_STATE_SYSTEM_COLLAPSED;
		}
		return wxACC_OK;
	} else {
		wxTreeItemId item = FindItem(ctrl, childId);
		if (item) {
			if (tree[childId]._nt == ParentNode) {
				if (ctrl->IsExpanded(item)) {
					*state |= wxACC_STATE_SYSTEM_EXPANDED;
				} else {
					*state |= wxACC_STATE_SYSTEM_COLLAPSED;
				}
			}
			if (item == ctrl->GetFocusedItem())
				*state |= wxACC_STATE_SYSTEM_FOCUSED;

			if (item == ctrl->GetSelection())
	         		*state |= wxACC_STATE_SYSTEM_SELECTED;
		}
	}
	return wxACC_OK;
}

// Returns a localized string representing the value for the object
// or child.
wxAccStatus TreeCtrlAx::GetValue(int childId, wxString* strValue) {
	strValue->Clear();
	return wxACC_OK;
}

//wxAccStatus TreeCtrlAx::Navigate(
//   wxNavDir navDir, int fromId, int* toId, wxAccessible** toObject)
//{
//   to do
//}

// Modify focus or selection
wxAccStatus TreeCtrlAx::Select(int childId, wxAccSelectionFlags selectFlags) {
	wxCHECK(GetWindow() != nullptr, wxACC_FAIL);
	wxTreeCtrl* ctrl = GetCtrl();
	if (!ctrl)
		return wxACC_FAIL;

	if (childId != wxACC_SELF) {
		int childCount;
		GetChildCount(&childCount);
		if (childId > childCount)
			return wxACC_FAIL;

		wxTreeItemId item = FindItem(ctrl, childId);
		if (item) {
			if (selectFlags == wxACC_SEL_TAKEFOCUS)
				ctrl->SetFocusedItem(item);
			else if (selectFlags == wxACC_SEL_TAKESELECTION)
				ctrl->SelectItem(item);
	      		else
				return wxACC_NOT_IMPLEMENTED;
			return wxACC_OK;
		}
	}
	return wxACC_NOT_IMPLEMENTED;
}

// Mac Accessible Window for wxComboBox

ComboBoxAx::ComboBoxAx(wxComboBox *ctrl) : wxAccessible(ctrl) {
}

ComboBoxAx::~ComboBoxAx() {}

wxAccStatus ComboBoxAx::GetChild(int childId, wxAccessible** child) {
	if (childId == wxACC_SELF) {
		*child = this;
	} else {
		*child = this;
	}
	return wxACC_OK;
}

wxAccStatus ComboBoxAx::GetRole(int childId, wxAccRole* role) {
	if (childId == wxACC_SELF) {
		*role = wxROLE_SYSTEM_COMBOBOX;
	} else {
		*role =	wxROLE_SYSTEM_LIST;
	}
	return wxACC_OK;
}

// Returns number of elements
wxAccStatus ComboBoxAx::GetChildCount(int* childCount) {
	wxComboBox* ctrl = GetCtrl();
	if (!ctrl)
		return wxACC_FAIL;

	*childCount = ctrl->GetCount();
	return wxACC_OK;
}

wxAccStatus ComboBoxAx::GetDefaultAction(int WXUNUSED(childId), wxString* actionName) {
	actionName->clear();

	return wxACC_OK;
}

// Returns the description for this object or a child.
wxAccStatus ComboBoxAx::GetDescription(int childId, wxString *description) {
	wxComboBox* ctrl = GetCtrl();
	if (!ctrl)
		return wxACC_FAIL;

	if (childId == wxACC_SELF) {
		*description = _("ComboBox - Use the arrow keys to navigate the list. Typing the first letter of an entry will navigate to that entry");
	} else {
		*description = ctrl->GetValue();
	}
	return wxACC_OK;
}

// Returns help text for this object or a child, similar to tooltip text.
wxAccStatus ComboBoxAx::GetHelpText(int childId, wxString *helpText) {
	helpText->clear();
	return wxACC_OK;
}

// Returns the keyboard shortcut for this object or child.
// Return e.g. ALT+K
wxAccStatus ComboBoxAx::GetKeyboardShortcut(int WXUNUSED(childId), wxString *shortcut) {
	shortcut->clear();

	return wxACC_OK;
}
wxAccStatus ComboBoxAx::Select(int childId, wxAccSelectionFlags selectFlags) {
	wxCHECK(GetWindow() != nullptr, wxACC_FAIL);
	wxComboBox* ctrl = GetCtrl();
	if (!ctrl)
		return wxACC_FAIL;

	if (childId != wxACC_SELF) {
		int childCount;
		GetChildCount(&childCount);
		if (childId > childCount)
			return wxACC_FAIL;

		if (selectFlags == wxACC_SEL_TAKEFOCUS)
			ctrl->SetFocus();
		else if (selectFlags == wxACC_SEL_TAKESELECTION)
			ctrl->SetSelection(childId);
      		else
			return wxACC_NOT_IMPLEMENTED;
		return wxACC_OK;
	}
	return wxACC_NOT_IMPLEMENTED;
}

wxAccStatus ComboBoxAx::GetName(int childId, wxString* name) {
	wxCHECK(GetWindow() != nullptr, wxACC_FAIL);

	*name = GetWindow()->GetName();
	return wxACC_OK;
}

// Returns a state constant.
wxAccStatus ComboBoxAx::GetState(int childId, long* state) {
	wxComboBox* ctrl = GetCtrl();
	if (!ctrl)
		return wxACC_FAIL;

	*state =  wxACC_STATE_SYSTEM_FOCUSABLE | wxACC_STATE_SYSTEM_SELECTABLE;

	if (childId != wxACC_SELF) {
		*state |= wxACC_STATE_SYSTEM_FOCUSED;

		if (childId == ctrl->GetSelection())
			*state |= wxACC_STATE_SYSTEM_SELECTED;
	}
	return wxACC_OK;
}

//wxAccStatus ComboBoxAx::Navigate(wxNavDir navDir, int fromId, int* toId, wxAccessible** toObject) {
//	return wxACC_OK;
//}

// Mac Accessible Window for Button

ButtonAx::ButtonAx(wxButton *ctrl) : wxAccessible(ctrl) {
}

ButtonAx::~ButtonAx() {}

wxAccStatus ButtonAx::GetRole(int childId, wxAccRole* role) {
	*role = wxROLE_SYSTEM_PUSHBUTTON;
	return wxACC_OK;
}

wxAccStatus ButtonAx::GetDescription(int childId, wxString *description) {
	wxCHECK(GetWindow() != nullptr, wxACC_FAIL);
	description->clear();
	*description = GetWindow()->GetName();

	return wxACC_OK;
}

wxAccStatus ButtonAx::GetName(int childId, wxString* name) {
	wxCHECK(GetWindow() != nullptr, wxACC_FAIL);

	// If the control has children, don't override their names
	if (childId > 0)
		return wxACC_NOT_IMPLEMENTED;
	*name = GetWindow()->GetName();
	return wxACC_OK;
}

// Returns a state constant.
wxAccStatus ButtonAx::GetState(int childId, long* state) {
	wxButton* ctrl = GetCtrl();
	if (!ctrl)
		return wxACC_FAIL;

	*state = 0;
	if (!ctrl->IsEnabled())
		*state |= wxACC_STATE_SYSTEM_UNAVAILABLE;
	return wxACC_OK;
}

#endif // __WXMAC__

#endif // wxUSE_ACCESSIBILITY
// Usability for combobox

void
tqslComboBox::OnTextEntry(TQ_WXTEXTEVENT& event) {
	static bool skipNext = false;

	if (skipNext) {
		skipNext = false;
		event.Skip();
		return;
	}
	wxComboBox *cb = static_cast<wxComboBox*>(event.GetEventObject());
	wxString val = cb->GetValue();
	// Does it start with (localized) "[None]" ?
	wxString none = wxGetTranslation(wxT("[None]"));

	// If so, strip that and check
	if (val.Left(none.size()) == none) {
		val = val.Right(val.size() - none.size());
	}

	if (val.size() == 1) {
		val = val.Upper();
		int cnt = cb->GetCount();
		int idx;
		for (idx = 0; idx < cnt; idx++) {
			wxString cur = cb->GetString(idx);
			if (cur.Left(val.size()) == val) {
				if (cur == val)		// Not changing
					break;
				skipNext = true;
				cb->SetValue(cur);
				cb->SetSelection(idx);
#if wxMAJOR_VERSION > 2
				cb->Popup();
#endif
				break;
			}
		}
	}
	event.Skip();
}
