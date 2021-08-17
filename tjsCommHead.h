
#ifndef __TjsCommHead_h__
#define __TjsCommHead_h__

#include <windows.h>
#include "tp_stub.h"

#ifndef tjs_string
#define tjs_string std::wstring
#endif

// [XXX]
struct eTJS {
	const ttstr message;
	eTJS(const ttstr& message) : message(message) {}
	const ttstr& GetMessage() const { return message; }
};

#endif
