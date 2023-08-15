
#ifndef __TVPBinaryStreamShim_h__
#define __TVPBinaryStreamShim_h__

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <objidl.h>
#include "tp_stub.h"

#ifndef NO_REDEFINE_CREATESTREAM
#define TVPCreateStream  CompatTJSBinaryStream::CreateStream
#define TVPCreateBinaryStreamForRead  CompatTJSBinaryStream::CreateStreamForRead
#define TVPCreateBinaryStreamForWrite  CompatTJSBinaryStream::CreateStreamForWrite
#define tTJSBinaryStream CompatTJSBinaryStream
#endif

//---------------------------------------------------------------------------
class CompatTJSBinaryStream
{
	IStream *Stream = NULL;
public:
	CompatTJSBinaryStream() {
	}
	CompatTJSBinaryStream(IStream *stream) : Stream(stream) {
		Stream->AddRef();
	}
	virtual ~CompatTJSBinaryStream() {
		if (Stream)
		{
			Stream->Release();
			Stream = NULL;
		}
	}

	virtual tjs_uint64 TJS_INTF_METHOD Seek(tjs_int64 offset, tjs_int whence) {
		if (!Stream)
		{
			return 0;
		}
		DWORD origin;

		switch(whence)
		{
		case TJS_BS_SEEK_SET:			origin = STREAM_SEEK_SET;		break;
		case TJS_BS_SEEK_CUR:			origin = STREAM_SEEK_CUR;		break;
		case TJS_BS_SEEK_END:			origin = STREAM_SEEK_END;		break;
		default:						origin = STREAM_SEEK_SET;		break;
		}

		LARGE_INTEGER ofs;
		ULARGE_INTEGER newpos;

		ofs.QuadPart = 0;
		HRESULT hr = Stream->Seek(ofs, STREAM_SEEK_CUR, &newpos);
		bool orgpossaved;
		LARGE_INTEGER orgpos;
		if(FAILED(hr))
		{
			orgpossaved = false;
		}
		else
		{
			orgpossaved = true;
			memcpy(&orgpos, &newpos, sizeof(orgpos));
		}

		ofs.QuadPart = offset;

		hr = Stream->Seek(ofs, origin, &newpos);
		if(FAILED(hr))
		{
			if(orgpossaved)
			{
				Stream->Seek(orgpos, STREAM_SEEK_SET, &newpos);
			}
			else
			{
				TVPThrowExceptionMessage(TJS_W("Seek error"));
			}
		}

		return newpos.QuadPart;
	}

	virtual tjs_uint TJS_INTF_METHOD Read(void *buffer, tjs_uint read_size) {
		if (!Stream)
		{
			return 0;
		}
		ULONG cb = read_size;
		ULONG read;
		HRESULT hr = Stream->Read(buffer, cb, &read);
		if(FAILED(hr)) read = 0;
		return read;
	}

	virtual tjs_uint64 TJS_INTF_METHOD GetSize() {
		if (!Stream)
		{
			return 0;
		}
		HRESULT hr;
		STATSTG stg;

		hr = Stream->Stat(&stg, STATFLAG_NONAME);
		if (SUCCEEDED(hr)) return (tjs_uint64)(stg.cbSize.QuadPart);

		tjs_uint64 orgpos = GetPosition();
		tjs_uint64 size = Seek(0, TJS_BS_SEEK_END);
		Seek(orgpos, TJS_BS_SEEK_SET);
		return size;
	}

	tjs_uint64 GetPosition() {
		return Seek(0, TJS_BS_SEEK_CUR);
	}

	void SetPosition(tjs_uint64 pos) {
		if(pos != Seek(pos, TJS_BS_SEEK_SET))
			TVPThrowExceptionMessage(TJS_W("Seek error"));
	}

	void ReadBuffer(void *buffer, tjs_uint read_size) {
		if(Read(buffer, read_size) != read_size)
			TVPThrowExceptionMessage(TJS_W("Read error"));
	}

	// reads little-endian integers
	inline tjs_uint64 ReadI64LE() {
		tjs_uint64 temp;
		ReadBuffer(&temp, 8);
		return temp;
	}
	inline tjs_uint32 ReadI32LE() {
		tjs_uint32 temp;
		ReadBuffer(&temp, 4);
		return temp;
	}
	inline tjs_uint16 ReadI16LE() {
		tjs_uint16 temp;
		ReadBuffer(&temp, 2);
		return temp;
	}

public:
	static tTJSBinaryStream* CreateStream(const ttstr & name , tjs_uint32 flags = 0)
	{
		IStream *Stream = TVPCreateIStream(name, flags);
		if(!Stream) return NULL;
		
		tTJSBinaryStream *CompatStream = new tTJSBinaryStream(Stream);
		Stream->Release();
		return CompatStream;
	}

	static tTJSBinaryStream* CreateStreamForRead(const ttstr & name , const ttstr & modestr)
	{
		// check o mode
		tTJSBinaryStream* stream = TVPCreateStream(name, TJS_BS_READ);

		const tjs_char* o_ofs = TJS_strchr(modestr.c_str(), TJS_W('o'));
		if(o_ofs != NULL) {
			// seek to offset
			o_ofs++;
			tjs_char buf[256];
			int i;
			for(i = 0; i < 255; i++) {
				if(o_ofs[i] >= TJS_W('0') && o_ofs[i] <= TJS_W('9'))
					buf[i] = o_ofs[i];
				else break;
			}
			buf[i] = 0;
			tjs_uint64 ofs = ttstr(buf).AsInteger();
			stream->SetPosition(ofs);
		}
		return stream;
	}

	static tTJSBinaryStream* CreateStreamForWrite(const ttstr & name , const ttstr & modestr)
	{
		tTJSBinaryStream* stream;
		// check o mode
		const tjs_char * o_ofs;
		o_ofs = TJS_strchr(modestr.c_str(), TJS_W('o'));
		if(o_ofs != NULL) {
			// seek to offset
			o_ofs++;
			tjs_char buf[256];
			int i;
			for(i = 0; i < 255; i++) {
				if(o_ofs[i] >= TJS_W('0') && o_ofs[i] <= TJS_W('9'))
					buf[i] = o_ofs[i];
				else break;
			}
			buf[i] = 0;
			tjs_uint64 ofs = ttstr(buf).AsInteger();
			stream = TVPCreateStream(name, TJS_BS_UPDATE);
			stream->SetPosition(ofs);
		} else {
			stream = TVPCreateStream(name, TJS_BS_WRITE);
		}
		return stream;
	}
};
#endif
