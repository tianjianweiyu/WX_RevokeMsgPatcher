#pragma once

#include <windows.h>

class WeChatCore
{

public:
	VOID Start();
	VOID StartHook();

	static WeChatCore* Instance()
	{
		static WeChatCore s_Instance;
		return &s_Instance;
	}

private:
	WeChatCore() :
		// 原始模块句柄
		m_hModule(NULL),
		m_Init(0){}

	VOID StartImp();


public:
	HMODULE m_hModule;        // 注入的模块的地址
	DWORD m_wechatwin_msver;         // 主版本号
	DWORD m_wechatwin_lsver;         // 次版本号
private:
	BOOL  m_Init;              // HOOK环境初始化Ok
};

