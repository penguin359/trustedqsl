/***************************************************************************
                          location.h  -  description
                             -------------------
    begin                : Fri Nov 15 2002
    copyright            : (C) 2002 by ARRL
    author               : Jon Bloom
    email                : jbloom@arrl.org
    revision             : $Id$
 ***************************************************************************/

#ifndef __location_h
#define __location_h

// TQSL_LOCATION_FIELD flag bits
#define TQSL_LOCATION_FIELD_UPPER	1
#define TQSL_LOCATION_FIELD_MUSTSEL 2
#define TQSL_LOCATION_FIELD_SELNXT 4

#include <string.h>
#include <vector>

#include "winstrdefs.h"

using std::vector;

class VUCCgrid {
 public:
	VUCCgrid(int ent, const char * pas, const char * grid) {
		_ent = ent;
		if (pas)
			_pas = strdup(pas);
		else
			_pas = NULL;
		_grid = strdup(grid);
	}
	int ent() { return _ent; }
	char* pas() { return _pas; }
	char* grid() { return _grid; }
 private:
	int _ent;
	char* _pas;
	char* _grid;
};

typedef vector<VUCCgrid> VUCCGridList;

#endif	// __location_h
