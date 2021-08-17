//---------------------------------------------------------------------------
/*
	TJS2 Script Engine
	Copyright (C) 2000 W.Dee <dee@kikyou.info> and contributors

	See details of license at "license.txt"
*/
//---------------------------------------------------------------------------
// utility functions
//---------------------------------------------------------------------------
#ifndef tjsUtilsH
#define tjsUtilsH


#if 1
#if 0
#include <mutex>
#endif
#else
#ifdef __WIN32__
#include <windows.h>
#else
#include <semaphore.h>
#endif
#endif
//---------------------------------------------------------------------------
// tTJSCriticalSection ( implement on each platform for multi-threading support )
//---------------------------------------------------------------------------
#if 1
class tTJSCriticalSection
{
#if 0
	std::recursive_mutex Mutex;
#endif

public:
	tTJSCriticalSection() {}
	~tTJSCriticalSection() {}

#if 0
	void Enter() { Mutex.lock(); }
	void Leave() { Mutex.unlock(); }
#endif
	void Enter() {  }
	void Leave() {  }
};
#else
#ifdef __WIN32__
class tTJSCriticalSection
{
	CRITICAL_SECTION CS;
public:
	tTJSCriticalSection() { InitializeCriticalSection(&CS); }
	~tTJSCriticalSection() { DeleteCriticalSection(&CS); }

	void Enter() { EnterCriticalSection(&CS); }
	void Leave() { LeaveCriticalSection(&CS); }
};
#else
// implements Semaphore
class tTJSCriticalSection
{
	sem_t Handle;
public:
	tTJSCriticalSection() { sem_init( &Handle, 0, 1 ); }
	~tTJSCriticalSection() { sem_destroy( &Handle ); }

	void Enter() { sem_wait( &Handle ); }
	void Leave() { sem_post( &Handle ); }
};
#endif
#endif
//---------------------------------------------------------------------------
// interlocked operation ( implement on each platform for multi-threading support )
//---------------------------------------------------------------------------
// refer C++11 atomic

//---------------------------------------------------------------------------
// tTJSCriticalSectionHolder
//---------------------------------------------------------------------------
class tTJSCriticalSectionHolder
{
	tTJSCriticalSection *Section;
public:
	tTJSCriticalSectionHolder(tTJSCriticalSection &cs)
	{
		Section = &cs;
		Section->Enter();
	}

	~tTJSCriticalSectionHolder()
	{
		Section->Leave();
	}

};
//typedef tTJSCriticalSectionHolder tTJSCSH;
//---------------------------------------------------------------------------

#endif




