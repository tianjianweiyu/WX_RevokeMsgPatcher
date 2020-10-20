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
		// ԭʼģ����
		m_hModule(NULL),
		m_Init(0){}

	VOID StartImp();


public:
	HMODULE m_hModule;        // ע���ģ��ĵ�ַ
	DWORD m_wechatwin_msver;         // ���汾��
	DWORD m_wechatwin_lsver;         // �ΰ汾��
private:
	BOOL  m_Init;              // HOOK������ʼ��Ok
};

