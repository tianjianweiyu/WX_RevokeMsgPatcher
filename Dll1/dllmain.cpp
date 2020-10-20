// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "WeChatCore.h"
#include <mmiscapi2.h>
#pragma comment(lib,"Winmm.lib")

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
#pragma comment(linker, "/EXPORT:GetFileVersionInfoA=versionOrg.GetFileVersionInfoA,@1")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoByHandle=versionOrg.GetFileVersionInfoByHandle,@2")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExA=versionOrg.GetFileVersionInfoExA,@3")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExW=versionOrg.GetFileVersionInfoExW,@4")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeA=versionOrg.GetFileVersionInfoSizeA,@5")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExA=versionOrg.GetFileVersionInfoSizeExA,@6")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExW=versionOrg.GetFileVersionInfoSizeExW,@7")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeW=versionOrg.GetFileVersionInfoSizeW,@8")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoW=versionOrg.GetFileVersionInfoW,@9")
#pragma comment(linker, "/EXPORT:VerFindFileA=versionOrg.VerFindFileA,@10")
#pragma comment(linker, "/EXPORT:VerFindFileW=versionOrg.VerFindFileW,@11")
#pragma comment(linker, "/EXPORT:VerInstallFileA=versionOrg.VerInstallFileA,@12")
#pragma comment(linker, "/EXPORT:VerInstallFileW=versionOrg.VerInstallFileW,@13")
#pragma comment(linker, "/EXPORT:VerLanguageNameA=versionOrg.VerLanguageNameA,@14")
#pragma comment(linker, "/EXPORT:VerLanguageNameW=versionOrg.VerLanguageNameW,@15")
#pragma comment(linker, "/EXPORT:VerQueryValueA=versionOrg.VerQueryValueA,@16")
#pragma comment(linker, "/EXPORT:VerQueryValueW=versionOrg.VerQueryValueW,@17")
///////////////////////////////////////////////////////

extern BOOL StartStatus;
extern BOOL HookTStatus;

VOID CALLBACK MyTimerProc(
	HWND hWnd, // handle of window for timer messages
	UINT uMsg, // WM_TIMER message
	UINT idEvent, // timer identifier
	DWORD dwTime // current system time
)
{
	if (!StartStatus)
	{
		return;
	}
	if (!HookTStatus)
	{
		WeChatCore::Instance()->StartHook();
	}
	return;
}

DWORD WINAPI Start(LPVOID lpParam)
{
	// 开始
	WeChatCore::Instance()->Start();

	timeSetEvent(500, 1, (LPTIMECALLBACK)MyTimerProc, NULL, TIME_PERIODIC);
	return 0;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		//MessageBoxA(NULL,"测试！",NULL,NULL);
		CreateThread(NULL, 0, Start, NULL, 0, NULL);
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

