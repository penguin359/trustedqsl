/***************************************************************************
	                       wxutil.h  -  description
	                          -------------------
	 begin                : Thu Aug 14 2003
	 copyright            : (C) 2003 by ARRL
	 author               : Jon Bloom
	 email                : jbloom@arrl.org
	 revision             : $Id$
 ***************************************************************************/

#ifndef __wxutil_h
#define __wxutil_h


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

#include <wx/intl.h>
#include <wx/treectrl.h>

// This macro marks a c-string to be extracted for translation. xgettext is directed to look for _() and __().

#define __(x) (x)

#if wxCHECK_VERSION(2, 5, 0)
	#define TQ_WXCLOSEEVENT wxCloseEvent
	#define TQ_WXTEXTEVENT wxCommandEvent
	#define TQ_WXCOOKIE wxTreeItemIdValue
#else
	#define TQ_WXCLOSEEVENT wxCommandEvent
	#define TQ_WXTEXTEVENT wxEvent
	#define TQ_WXCOOKIE long
#endif

wxSize getTextSize(wxWindow *win);
wxString wrapString(wxWindow *win, wxString in, int length);
wxString urlEncode(wxString& str);
int utf8_to_ucs2(const char *in, char *out, size_t buflen);
int getPasswordFromUser(wxString& result, const wxString& message, const wxString& caption, const wxString& defaultValue, wxWindow *parent);
wxString getLocalizedErrorString(void);
wxLanguage langWX2toWX3(wxLanguage wx2);


#if defined(__WXMAC__)
#include <wx/setup.h>

#if wxUSE_ACCESSIBILITY
#include <wx/access.h>

// Class overrides description to get control name

class WindowAccessible: public wxAccessible {
 public:
	explicit WindowAccessible(wxWindow* win);
	virtual ~WindowAccessible() {}

	wxAccStatus GetName(int childId, wxString* name);
};

#if (wxMAJOR_VERSION > 2)
// Define a custom class
class TreeCtrlAx : public WindowAccessible {
 public:
	explicit TreeCtrlAx(wxTreeCtrl * ctrl);
	virtual ~TreeCtrlAx();

	wxAccStatus GetChild(int childId, wxAccessible** child);

	wxAccStatus GetChildCount(int* childCount);

	wxAccStatus GetDefaultAction(int childId, wxString *actionName);

	// Returns the description for this object or a child.
	wxAccStatus GetDescription(int childId, wxString *description);

	// Gets the window with the keyboard focus.
	// If childId is 0 and child is NULL, no object in
	// this subhierarchy has the focus.
	// If this object has the focus, child should be 'this'.
	wxAccStatus GetFocus(int *childId, wxAccessible **child);

	// Returns help text for this object or a child, similar to tooltip text.
	wxAccStatus GetHelpText(int childId, wxString *helpText);

	// Returns the keyboard shortcut for this object or child.
	// Return e.g. ALT+K
	wxAccStatus GetKeyboardShortcut(int childId, wxString *shortcut);

	// Returns the rectangle for this object (id = 0) or a child element (id > 0).
	// Gets the name of the specified object.
	wxAccStatus GetLocation(wxRect& rect, int elementId);

	// Gets the name of the specified object
	wxAccStatus GetName(int childId, wxString *name);

	// Returns a role constant.
	wxAccStatus GetRole(int childId, wxAccRole *role);

	// Gets a variant representing the selected children
	// of this object.
	// Acceptable values:
	// - a null variant (IsNull() returns TRUE)
	// - a list variant (GetType() == wxT("list"))
	// - an integer representing the selected child element,
	//   or 0 if this object is selected (GetType() == wxT("long"))
	// - a "void*" pointer to a wxAccessible child object
	//wxAccStatus GetSelections(wxVariant *selections);
	// leave unimplemented

	// Returns a state constant.
	wxAccStatus GetState(int childId, long* state);

	// Returns a localized string representing the value for the object
	// or child.
	wxAccStatus GetValue(int childId, wxString* strValue);

	// Navigates from fromId to toId/toObject
	// wxAccStatus Navigate(wxNavDir navDir, int fromId, int* toId, wxAccessible** toObject);

	// Modify focus or selection
	wxAccStatus Select(int childId, wxAccSelectionFlags selectFlags);

 private:
	wxTreeCtrl *GetCtrl() { return static_cast<wxTreeCtrl*>( GetWindow() ); }
};

class ComboBoxAx /* final */ : public wxAccessible {
 public:
	explicit ComboBoxAx(wxComboBox * ctrl);
	virtual ~ComboBoxAx();

	wxAccStatus GetChild(int childId, wxAccessible** child);

	wxAccStatus GetChildCount(int* childCount);

	wxAccStatus GetDefaultAction(int childId, wxString *actionName);

	// Returns the description for this object or a child.
	wxAccStatus GetDescription(int childId, wxString *description);

	// Returns help text for this object or a child, similar to tooltip text.
	wxAccStatus GetHelpText(int childId, wxString *helpText);

	// Returns the keyboard shortcut for this object or child.
	// Return e.g. ALT+K
	wxAccStatus GetKeyboardShortcut(int childId, wxString *shortcut);

	// Returns the name for this object (id = 0) or a child element (id > 0).
	wxAccStatus GetName(int childId, wxString *name);

	// Returns a role constant.
	wxAccStatus GetRole(int childId, wxAccRole *role);

	// Gets a variant representing the selected children
	// of this object.
	//wxAccStatus GetSelections(wxVariant *selections);
	// leave unimplemented

	// Returns a state constant.
	wxAccStatus GetState(int childId, long* state);

	// Navigates from fromId to toId/toObject
	// wxAccStatus Navigate(wxNavDir navDir, int fromId, int* toId, wxAccessible** toObject);

	// Modify focus or selection
	wxAccStatus Select(int childId, wxAccSelectionFlags selectFlags);

	// Keystroke handler
	void OnChar(wxKeyEvent& event);

 private:
	wxComboBox *GetCtrl() { return static_cast<wxComboBox *>( GetWindow() ); }
};

class ButtonAx /* final */ : public wxAccessible {
 public:
	explicit ButtonAx(wxButton * ctrl);
	virtual ~ButtonAx();

	// Returns the description for this object or a child.
	wxAccStatus GetDescription(int childId, wxString *description);

	// Returns a role constant.
	wxAccStatus GetRole(int childId, wxAccRole *role);

	// Returns a state constant.
	wxAccStatus GetState(int childId, long* state);

	// Returns the name of the control
	wxAccStatus GetName(int childId, wxString *name);

 private:
	wxButton *GetCtrl() { return static_cast<wxButton *>( GetWindow() ); }
};

#endif		// wx3 or later
#endif		// wxUSE_ACCESSIBILITY
#endif		// __WXMAC__

// ComboBox with prefix entry

class tqslComboBox : public wxComboBox {
 public:
	tqslComboBox(wxWindow *parent, wxWindowID id, const wxString &value = wxEmptyString,
			const wxPoint &pos = wxDefaultPosition, const wxSize &size = wxDefaultSize,
			int n = 0, const wxString choices[] = NULL, long style = 0,
			const wxValidator &validator = wxDefaultValidator,
			const wxString &name = wxComboBoxNameStr) :
				wxComboBox(parent, id, value, pos, size, n,  choices, style, validator, name) {}
	virtual bool AcceptsFocusFromKeyboard() const { return true; }
	void OnTextEntry(TQ_WXTEXTEVENT&);
};

class tqslTreeCtrl : public wxTreeCtrl {
 public:
	tqslTreeCtrl(wxWindow *parent, wxWindowID id = wxID_ANY, const wxPoint &pos = wxDefaultPosition,
			const wxSize &size = wxDefaultSize, long style = wxTR_DEFAULT_STYLE,
			const wxValidator &validator = wxDefaultValidator, const wxString &name = wxTreeCtrlNameStr) :
				wxTreeCtrl(parent, id, pos, size, style, validator, name) {}
	virtual bool AcceptsFocusFromKeyboard() const { return true; }
};


// Macro for accesibility add-ons for controls
#if (wxUSE_ACCESSIBILITY && defined(__WXMAC__) && wxMAJOR_VERSION > 2)
#define ACCESSIBLE(x, y) (x)->SetAccessible(new y((x)));
#else
#define ACCESSIBLE(x, y)
#endif

#endif	// __wxutil_h
