/***************************************************************************
                          wxutil.cpp  -  description
                             -------------------
    begin                : Thu Aug 14 2003
    copyright            : (C) 2003 by ARRL
    author               : Jon Bloom
    email                : jbloom@arrl.org
    revision             : $Id: wxutil.cpp,v 1.1 2003/08/14 18:32:02 jbloom Exp $
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "sysconfig.h"
#endif

#include "wxutil.h"

wxSize
getTextSize(wxWindow *win) {
	wxClientDC dc(win);
	wxCoord char_width, char_height;
	dc.GetTextExtent(wxString("M"), &char_width, &char_height);
	return wxSize(char_width, char_height);
}

