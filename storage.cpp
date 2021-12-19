#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "ncbind/ncbind.hpp"
#include <map>
#include <vector>

#include <stdio.h>
#include <stdlib.h>

#include "cxdec.h"

#include "tp_stub.h"

#include "XP3Archive.h"

#undef tTJSBinaryStream

class XP3Stream : public IStream {

public:
	XP3Stream(CompatTJSBinaryStream *in_vfd)
	{
		ref_count = 1;
		vfd = in_vfd;
	}

	// IUnknown
	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject)
	{
		if (riid == IID_IUnknown || riid == IID_ISequentialStream || riid == IID_IStream)
		{
			if (ppvObject == NULL)
				return E_POINTER;
			*ppvObject = this;
			AddRef();
			return S_OK;
		}
		else
		{
			*ppvObject = 0;
			return E_NOINTERFACE;
		}
	}

	ULONG STDMETHODCALLTYPE AddRef(void)
	{
		ref_count++;
		return ref_count;
	}
	
	ULONG STDMETHODCALLTYPE Release(void)
	{
		int ret = --ref_count;
		if (ret <= 0) {
			delete this;
			ret = 0;
		}
		return ret;
	}

	// ISequentialStream
	HRESULT STDMETHODCALLTYPE Read(void *pv, ULONG cb, ULONG *pcbRead)
	{
		try
		{
			ULONG read;
			read = vfd->Read(pv, cb);
			if(pcbRead) *pcbRead = read;
		}
		catch(...)
		{
			return E_FAIL;
		}
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE Write(const void *pv, ULONG cb, ULONG *pcbWritten)
	{
		return E_NOTIMPL;
	}

	// IStream
	HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER dlibMove,	DWORD dwOrigin, ULARGE_INTEGER *plibNewPosition)
	{
		try
		{
			switch(dwOrigin)
			{
			case STREAM_SEEK_SET:
				if(plibNewPosition)
					(*plibNewPosition).QuadPart =
						vfd->Seek(dlibMove.QuadPart, TJS_BS_SEEK_SET);
				else
						vfd->Seek(dlibMove.QuadPart, TJS_BS_SEEK_SET);
				break;
			case STREAM_SEEK_CUR:
				if(plibNewPosition)
					(*plibNewPosition).QuadPart =
						vfd->Seek(dlibMove.QuadPart, TJS_BS_SEEK_CUR);
				else
						vfd->Seek(dlibMove.QuadPart, TJS_BS_SEEK_CUR);
				break;
			case STREAM_SEEK_END:
				if(plibNewPosition)
					(*plibNewPosition).QuadPart =
						vfd->Seek(dlibMove.QuadPart, TJS_BS_SEEK_END);
				else
						vfd->Seek(dlibMove.QuadPart, TJS_BS_SEEK_END);
				break;
			default:
				return E_FAIL;
			}
		}
		catch(...)
		{
			return E_FAIL;
		}
		return S_OK;
	}
	
	HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER libNewSize)
	{
		return E_NOTIMPL;
	}
	
	HRESULT STDMETHODCALLTYPE CopyTo(IStream *pstm, ULARGE_INTEGER cb, ULARGE_INTEGER *pcbRead, ULARGE_INTEGER *pcbWritten)
	{
		return E_NOTIMPL;
	}

	HRESULT STDMETHODCALLTYPE Commit(DWORD grfCommitFlags)
	{
		return E_NOTIMPL;
	}

	HRESULT STDMETHODCALLTYPE Revert(void)
	{
		return E_NOTIMPL;
	}

	HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType)
	{
		return E_NOTIMPL;
	}
	
	HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER libOffset, ULARGE_INTEGER cb, DWORD dwLockType)
	{
		return E_NOTIMPL;
	}
	
	HRESULT STDMETHODCALLTYPE Stat(STATSTG *pstatstg, DWORD grfStatFlag)
	{
		// This method imcompletely fills the target structure, because some
		// informations like access mode or stream name are already lost
		// at this point.

		if(pstatstg)
		{
			ZeroMemory(pstatstg, sizeof(*pstatstg));

#if 0
			// pwcsName
			// this object's storage pointer does not have a name ...
			if(!(grfStatFlag &  STATFLAG_NONAME))
			{
				// anyway returns an empty string
				LPWSTR str = (LPWSTR)CoTaskMemAlloc(sizeof(*str));
				if(str == NULL) return E_OUTOFMEMORY;
				*str = TJS_W('\0');
				pstatstg->pwcsName = str;
			}
#endif

			// type
			pstatstg->type = STGTY_STREAM;

			// cbSize
			pstatstg->cbSize.QuadPart = vfd->GetSize();

			// mtime, ctime, atime unknown

			// grfMode unknown
			pstatstg->grfMode = STGM_DIRECT | STGM_READWRITE | STGM_SHARE_DENY_WRITE ;
				// Note that this method always returns flags above, regardless of the
				// actual mode.
				// In the return value, the stream is to be indicated that the
				// stream can be written, but of cource, the Write method will fail
				// if the stream is read-only.

			// grfLockSuppoted
			pstatstg->grfLocksSupported = 0;

			// grfStatBits unknown
		}
		else
		{
			return E_INVALIDARG;
		}

		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE Clone(IStream **ppstm)
	{
		return E_NOTIMPL;
	}

protected:
	/**
	 * デストラクタ
	 */
	virtual ~XP3Stream()
	{
		delete vfd;
		vfd = NULL;
	}

private:
	int ref_count;
	CompatTJSBinaryStream *vfd;
};

class XP3Storage : public iTVPStorageMedia
{

public:
	XP3Storage(tTVPXP3Archive *in_fs)
	{
		ref_count = 1;
		fs = in_fs;
		char buf[(sizeof(void *) * 2) + 1];
		snprintf(buf, (sizeof(void *) * 2) + 1, "%p", this);
		// The hash function does not work properly with numbers, so change to letters.
		char *p = buf;
		while(*p)
		{
			if(*p >= '0' && *p <= '9')
				*p = 'g' + (*p - '0');
			p++;
		}
		name = ttstr(TJS_W("xpk")) + buf;
	}

	virtual ~XP3Storage()
	{
		if (fs)
		{
			delete fs;
			fs = NULL;
		}
	}

public:
	// -----------------------------------
	// iTVPStorageMedia Intefaces
	// -----------------------------------

	virtual void TJS_INTF_METHOD AddRef()
	{
		ref_count++;
	};

	virtual void TJS_INTF_METHOD Release()
	{
		if (ref_count == 1)
		{
			delete this;
		}
		else
		{
			ref_count--;
		}
	};

	// returns media name like "file", "http" etc.
	virtual void TJS_INTF_METHOD GetName(ttstr &out_name)
	{
		out_name = name;
	}

	//	virtual ttstr TJS_INTF_METHOD IsCaseSensitive() = 0;
	// returns whether this media is case sensitive or not

	// normalize domain name according with the media's rule
	virtual void TJS_INTF_METHOD NormalizeDomainName(ttstr &name)
	{
		// normalize domain name
		// make all characters small
		tjs_char *p = name.Independ();
		while(*p)
		{
			if(*p >= TJS_W('A') && *p <= TJS_W('Z'))
				*p += TJS_W('a') - TJS_W('A');
			p++;
		}
	}

	// normalize path name according with the media's rule
	virtual void TJS_INTF_METHOD NormalizePathName(ttstr &name)
	{
		// normalize path name
		// make all characters small
		tjs_char *p = name.Independ();
		while(*p)
		{
			if(*p >= TJS_W('A') && *p <= TJS_W('Z'))
				*p += TJS_W('a') - TJS_W('A');
			p++;
		}
	}

	// check file existence
	virtual bool TJS_INTF_METHOD CheckExistentStorage(const ttstr &name)
	{
		const tjs_char *ptr = name.c_str();

		// The domain name needs to be "."
		if (!TJS_strncmp(ptr, TJS_W("./"), 2))
		{
			ptr += 2;
			ttstr fname(ptr);
			tTVPArchive::NormalizeInArchiveStorageName(fname);
			return fs->IsExistent(fname);
		}
		return false;
	}

	// open a storage and return a tTJSBinaryStream instance.
	// name does not contain in-archive storage name but
	// is normalized.
	virtual tTJSBinaryStream * TJS_INTF_METHOD Open(const ttstr & name, tjs_uint32 flags) {
		if (flags == TJS_BS_READ)
		{
			const tjs_char *ptr = name.c_str();

			// The domain name needs to be "."
			if (!TJS_strncmp(ptr, TJS_W("./"), 2))
			{
				ptr += 2;
				ttstr fname(ptr);
				tTVPArchive::NormalizeInArchiveStorageName(fname);
				CompatTJSBinaryStream *stream = fs->CreateStream(fname);
				if (stream)
				{
					IStream *streamm = new XP3Stream(stream);
					if (streamm)
					{
						tTJSBinaryStream *ret = TVPCreateBinaryStreamAdapter(streamm);
						streamm->Release();
						return ret;
					}
				}
			}
		}
		return NULL;
	}

	// list files at given place
	virtual void TJS_INTF_METHOD GetListAt(const ttstr &name, iTVPStorageLister * lister)
	{
		const tjs_char *ptr = name.c_str();

		// The domain name needs to be "."
		if (!TJS_strncmp(ptr, TJS_W("./"), 2))
		{
			ptr += 2;
			// Skip extra slashes
			while (*ptr)
			{
				if (!TJS_strncmp(ptr, TJS_W("/"), 1))
				{
					ptr += 1;
				}
				else
				{
					break;
				}
			}
			ttstr fname(ptr);
			tTVPArchive::NormalizeInArchiveStorageName(fname);
			// TODO: handle directories correctly
			// Basic logic: trim leading name
			int count = fs->GetCount();
			for (int i = 0; i < count; i += 1)
			{
				ttstr filename = fs->GetName(i);
				tTVPArchive::NormalizeInArchiveStorageName(filename);
				// Skip directory
				if (filename.StartsWith(fname))
				{
					const tjs_char *ptr2 = filename.c_str() + fname.GetLen();
					ttstr fname(ptr2);
					// Only add files directly in level
					if (!TJS_strstr(ptr2, TJS_W("/")))
					{
						lister->Add(ptr2);
					}
				}
			}
		}
		else
		{
			TVPAddLog(ttstr("Unable to search in: '") + ttstr(name) + ttstr("'"));
		}
	}

	// basically the same as above,
	// check wether given name is easily accessible from local OS filesystem.
	// if true, returns local OS native name. otherwise returns an empty string.
	virtual void TJS_INTF_METHOD GetLocallyAccessibleName(ttstr &name)
	{
		name = "";
	}

	virtual void TJS_INTF_METHOD SetArchiveExtractionFilter(tTVPXP3ArchiveExtractionFilterWithUserdata filter, void *filterdata)
	{
		fs->SetArchiveExtractionFilter(filter, filterdata);
	}

private:
	tjs_uint ref_count;
	ttstr name;
	tTVPXP3Archive *fs;
};

static std::vector<XP3Storage*> storage_media_vector;

class XP3Encryption
{
public:
	XP3Encryption()
	{
		char buf[(sizeof(void *) * 2) + 1];
		snprintf(buf, (sizeof(void *) * 2) + 1, "%p", this);
		// The hash function does not work properly with numbers, so change to letters.
		char *p = buf;
		while(*p)
		{
			if(*p >= '0' && *p <= '9')
				*p = 'g' + (*p - '0');
			if(*p >= 'A' && *p <= 'Z')
				*p |= 32;
			p++;
		}
		name = ttstr(TJS_W("enc")) + buf;
		filter = NULL;
	}

	virtual ~XP3Encryption()
	{
	}

	virtual void TJS_INTF_METHOD GetName(ttstr &out_name)
	{
		out_name = name;
	}

	virtual void TJS_INTF_METHOD Filter(tTVPXP3ExtractionFilterInfo *info)
	{
	}

	static void TVP_tTVPXP3ArchiveExtractionFilter_CONVENTION FilterExec(tTVPXP3ExtractionFilterInfo *info, void *data)
	{
		if (info->SizeOfSelf != sizeof(tTVPXP3ExtractionFilterInfo))
		{
			TVPThrowExceptionMessage(TJS_W("Incompatible tTVPXP3ExtractionFilterInfo size"));
		}
		((XP3Encryption *)data)->Filter(info);
	}

	virtual void TJS_INTF_METHOD GetArchiveExtractionFilter(tTVPXP3ArchiveExtractionFilterWithUserdata &out_filter, void * &out_data)
	{
		out_filter = FilterExec;
		out_data = this;
	}

private:
	ttstr name;
	tTVPXP3ArchiveExtractionFilterWithUserdata filter;
};

static std::vector<XP3Encryption*> xp3_encryption_vector;

class XP3CxdecEncryption : public XP3Encryption
{
public:
	XP3CxdecEncryption(cxdec_information *in_information) : XP3Encryption()
	{
		memcpy(&information, in_information, sizeof(*in_information));
		memset(&state, 0, sizeof(state));
		cxdec_init(&state, &information);
	}

	virtual ~XP3CxdecEncryption()
	{
		cxdec_release(&state);
	}

	virtual void TJS_INTF_METHOD Filter(tTVPXP3ExtractionFilterInfo *info)
	{
		cxdec_decode(&state, &information, info->FileHash, (DWORD)(info->Offset), (PBYTE)(info->Buffer), (DWORD)(info->BufferSize));
	}

private:
	cxdec_information information;
	cxdec_state state;
};

class StoragesXP3File {

public:
	static ttstr mountXP3(ttstr filename)
	{
		{
			{
				tTVPXP3Archive * arc = NULL;
				try
				{
					if (TVPIsXP3Archive(filename))
					{
						arc = new tTVPXP3Archive(filename);
						if (arc)
						{
							XP3Storage * xp3storage = new XP3Storage(arc);
							TVPRegisterStorageMedia(xp3storage);
							storage_media_vector.push_back(xp3storage);
							ttstr xp3storage_name;
							xp3storage->GetName(xp3storage_name);
							return xp3storage_name;
						}
					}
				}
				catch(...)
				{
					return TJS_W("");
				}
			}
		}
		return TJS_W("");
	}

	static bool setEncryptionXP3(ttstr medianame, ttstr encryptionmethod)
	{
		for (auto i = storage_media_vector.begin();
			i != storage_media_vector.end(); i += 1)
		{
			ttstr this_medianame;
			(*i)->GetName(this_medianame);
			if (medianame == this_medianame)
			{
				if (encryptionmethod.GetLen() == 0)
				{
					(*i)->SetArchiveExtractionFilter(NULL, NULL);
					return true;
				}
				else
				{
					for (auto j = xp3_encryption_vector.begin();
						j != xp3_encryption_vector.end(); j += 1)
					{
						ttstr this_encryptionmethod;
						(*j)->GetName(this_encryptionmethod);
						if (encryptionmethod == this_encryptionmethod)
						{
							tTVPXP3ArchiveExtractionFilterWithUserdata this_encryptionfilter;
							void *this_encryptionfilterdata;
							(*j)->GetArchiveExtractionFilter(this_encryptionfilter, this_encryptionfilterdata);
							(*i)->SetArchiveExtractionFilter(this_encryptionfilter, this_encryptionfilterdata);
							return true;
						}
					}
				}
				return false;
			}
		}
		return false;
	}

	static ttstr loadEncryptionMethodCxdec(tTJSVariant encryption_var)
	{
		cxdec_information information_tmp;
		ncbPropAccessor encryption_accessor(encryption_var);
		int max_count = encryption_accessor.GetArrayCount();
		if (max_count >= 6)
		{
			tTJSVariant tmp_var;
			if (encryption_accessor.checkVariant(0, tmp_var))
			{
				ncbPropAccessor tmp_accessor(tmp_var);
				if (tmp_accessor.GetArrayCount() >= (int)sizeof(information_tmp.xcode_building_first_stage_order))
				{
					for (int i = 0; i < (int)sizeof(information_tmp.xcode_building_first_stage_order); i += 1)
					{
						information_tmp.xcode_building_first_stage_order[i] = (uint8_t)tmp_accessor.getIntValue(i);
					}
				}
				else
				{
					return TJS_W("");
				}
			}
			else
			{
				return TJS_W("");
			}
			if (encryption_accessor.checkVariant(1, tmp_var))
			{
				ncbPropAccessor tmp_accessor(tmp_var);
				if (tmp_accessor.GetArrayCount() >= (int)sizeof(information_tmp.xcode_building_stage_0_order))
				{
					for (int i = 0; i < (int)sizeof(information_tmp.xcode_building_stage_0_order); i += 1)
					{
						information_tmp.xcode_building_stage_0_order[i] = (uint8_t)tmp_accessor.getIntValue(i);
					}
				}
				else
				{
					return TJS_W("");
				}
			}
			else
			{
				return TJS_W("");
			}
			if (encryption_accessor.checkVariant(2, tmp_var))
			{
				ncbPropAccessor tmp_accessor(tmp_var);
				if (tmp_accessor.GetArrayCount() >= (int)sizeof(information_tmp.xcode_building_stage_1_order))
				{
					for (int i = 0; i < (int)sizeof(information_tmp.xcode_building_stage_1_order); i += 1)
					{
						information_tmp.xcode_building_stage_1_order[i] = (uint8_t)tmp_accessor.getIntValue(i);
					}
				}
				else
				{
					return TJS_W("");
				}
			}
			else
			{
				return TJS_W("");
			}
			if (encryption_accessor.checkVariant(3, tmp_var))
			{
				information_tmp.boundary_mask = (uint16_t)tmp_var.AsInteger();
			}
			else
			{
				return TJS_W("");
			}
			if (encryption_accessor.checkVariant(4, tmp_var))
			{
				information_tmp.boundary_offset = (uint16_t)tmp_var.AsInteger();
			}
			else
			{
				return TJS_W("");
			}
			if (encryption_accessor.checkVariant(5, tmp_var))
			{
				if (tmp_var.Type() == tvtOctet)
				{
					const tTJSVariantOctet *oct = tmp_var.AsOctetNoAddRef();
					if (oct->GetLength() == (int)sizeof(information_tmp.encryption_control_block))
					{
						memcpy(information_tmp.encryption_control_block, oct->GetData(), (int)sizeof(information_tmp.encryption_control_block));
					}
					else
					{
						return TJS_W("");
					}
				}
				else
				{
					return TJS_W("");
				}
			}
			else
			{
				return TJS_W("");
			}
			{
				XP3CxdecEncryption * xp3cxdecencryption = new XP3CxdecEncryption(&information_tmp);
				xp3_encryption_vector.push_back(xp3cxdecencryption);
				ttstr xp3cxdecencryption_name;
				xp3cxdecencryption->GetName(xp3cxdecencryption_name);
				return xp3cxdecencryption_name;
			}
		}
		return TJS_W("");
	}

	static bool unmountXP3(ttstr medianame)
	{
		for (auto i = storage_media_vector.begin();
			i != storage_media_vector.end(); i += 1)
		{
			ttstr this_medianame;
			(*i)->GetName(this_medianame);
			if (medianame == this_medianame)
			{
				TVPUnregisterStorageMedia(*i);
				(*i)->Release();
				storage_media_vector.erase(i);
				return true;
			}
		}

		return false;
	}
};

NCB_ATTACH_CLASS(StoragesXP3File, Storages) {
	NCB_METHOD(mountXP3);
	NCB_METHOD(loadEncryptionMethodCxdec);
	NCB_METHOD(setEncryptionXP3);
	NCB_METHOD(unmountXP3);
};


static HMODULE this_hmodule = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD Reason, LPVOID lpReserved)
{
	if (Reason == DLL_PROCESS_ATTACH)
	{
		this_hmodule = hModule;
		if (hModule != NULL)
		{
			DisableThreadLibraryCalls(hModule);
		}
	}
	return TRUE;
}

static void PreRegistCallback()
{
}

static void PostUnregistCallback()
{
	for (auto i = storage_media_vector.begin();
		i != storage_media_vector.end(); i += 1)
	{
		TVPUnregisterStorageMedia(*i);
	}
}

NCB_PRE_REGIST_CALLBACK(PreRegistCallback);
NCB_POST_UNREGIST_CALLBACK(PostUnregistCallback);
