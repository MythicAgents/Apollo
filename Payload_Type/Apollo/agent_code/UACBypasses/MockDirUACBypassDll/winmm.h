#ifndef __MAIN_H__
#define __MAIN_H__
#include <windows.h>
#define DLL_EXPORT __declspec(dllexport)
#ifdef __cplusplus
extern "C"
{
#endif
	void timeBeginPeriod();
	void timeEndPeriod();
	void timeGetTime();
	void waveOutGetNumDevs();

#ifdef __cplusplus
}
#endif
#endif // __MAIN_H__#pragma once