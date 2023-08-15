
#ifndef __TjsCommHead_h__
#define __TjsCommHead_h__

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <objidl.h>
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
