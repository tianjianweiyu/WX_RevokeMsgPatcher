#include "pch.h"
#include "WeChatCore.h"

#include <atlstr.h>
#include <strsafe.h>
#include <stdlib.h>
#include <tchar.h>

#pragma comment(lib,"Version.lib")

#define _WECHATFLAG_W     L"[WECHATCores...] "
#define UtlAlloc(size)    HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size))
#define UtlFree(p)        HeapFree(GetProcessHeap(), 0, (p))

BOOL StartStatus = FALSE;
BOOL HookTStatus = FALSE;


BYTE g_RelCode[5] = { 0 };

typedef struct _wxstring {
	LPWSTR data;
	DWORD len;
	DWORD maxlen;
} wxstring, *lpwxstring;

// Hook 撤回消息的原型
typedef VOID(_stdcall* TxRevokeMsg3_0_0_47)();
TxRevokeMsg3_0_0_47   RelTxRevokeMsg3_0_0_47 = NULL;

// 打印日志到调试器
void _cdecl MyAttW(LPCWSTR lpszFormat, ...)
{
	va_list args;
	va_start(args, lpszFormat);

	WCHAR szBuffer[0x500];
	WCHAR szOutText[0x500 + 20];

	HRESULT hr = StringCbVPrintfW(szBuffer, sizeof(szBuffer), lpszFormat, args);

	StringCbCopyW(szOutText, sizeof(szOutText), _WECHATFLAG_W);

	StringCbCatW(szOutText, sizeof(szOutText), szBuffer);

	OutputDebugStringW(szOutText);
	va_end(args);
}


/*!
*  函 数 名： GetPEVersion
*  日    期： 2020/10/16
*  返回类型： BOOL
*  参    数： LPCWSTR path 文件路径
*  参    数： DWORD * msver 接收主版本号
*  参    数： DWORD * lsver 接收次版本号
*  功    能： 获取指定文件的版本信息，成功返回TRUE,失败返回FALSE
*/
BOOL GetPEVersion(LPCWSTR path, DWORD *msver, DWORD *lsver)
{
	BOOL status = FALSE;
	PVOID info = NULL;
	DWORD handle = 0;
	VS_FIXEDFILEINFO* vsinfo = NULL;
	UINT vsinfolen = 0;
	//获取版本信息，成功返回版本信息的大小，失败返回0
	DWORD infolen = GetFileVersionInfoSizeW(path, &handle);
	//如果成功获取版本信息
	if (infolen)
	{
		//申请空间存放版本信息
		info = malloc(infolen);
		if (info)
		{
			//获取指定文件的版本信息资源
			if (GetFileVersionInfoW(path, handle, infolen, info))
			{
				//从指定的版本信息资源中检索指定的版本信息
				if (VerQueryValue(info, _T("\\"), (void**)&vsinfo, &vsinfolen))
				{
					if (msver)
					{
						*msver = vsinfo->dwFileVersionMS;
					}

					if (lsver)
					{
						*lsver = vsinfo->dwFileVersionLS;
					}

					status = TRUE;
				}
			}

			free(info);
		}
	}

	return status;
}

/*!
*  函 数 名： GetPECodeSectionSize
*  日    期： 2020/10/17
*  返回类型： DWORD
*  参    数： HMODULE hDllBase 模块基址
*  参    数： LPDWORD pBaseOfCode 接收模块代码段起始地址
*  功    能： 获取指定模块代码段的起始地址与大小，大小通过返回值获得，失败为0
*/
DWORD GetPECodeSectionSize(HMODULE hDllBase, LPDWORD pBaseOfCode)
{
	DWORD dwCodeSize = 0;
	do
	{
		HMODULE hModule = hDllBase;
		if (!hModule)
			break;

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
		if (hModule == NULL)
		{
			break;
		}
		__try
		{
			if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			{
				break;
			}

			PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
			if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
			{
				break;
			}

			if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0)
			{
				break;
			}

			dwCodeSize = pNtHeader->OptionalHeader.SizeOfCode;

			if (pBaseOfCode)
			{
				*pBaseOfCode = pNtHeader->OptionalHeader.BaseOfCode;
			}

		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return dwCodeSize;
		}

	} while (FALSE);

	return dwCodeSize;
}

// 搜索特征函数
PVOID FastSearch(PVOID addr, DWORD len, PUCHAR target, DWORD target_len)
{
	PVOID status = NULL;
	DWORD i = 0, j = 0;
	PUCHAR cur = (PUCHAR)addr;
	PUCHAR target_cur = (PUCHAR)target;
	BOOL bBadPoint = FALSE;

	for (i = 0; i < len; i++)
	{
		for (j = 0; j < target_len && (i + j) < len; j++)
		{
			// 判断指针地址是否有效
			// 如果对指定内存处没有读取权限，返回非零
			if (IsBadReadPtr((const void*)&cur[i + j], 1))
			{
				bBadPoint = TRUE;
				break;
			}

			// 0xCB位置是重定位地址，因为重定位地址每次启动可能不一样
			// 所以使用0xCB替代该处数据
			if (cur[i + j] != target_cur[j] && 0xcb != target_cur[j])
			{
				break;
			}
		}

		if (bBadPoint)
			break;

		if (j == target_len)
		{
			status = &cur[i];
			break;
		}
	}
	return status;
}

// 修改指定地址处一字节的数据
static BOOL PatchMemoryUCHAR(
	__in const PVOID pAddr,
	__in const UCHAR uChar)
{
	DWORD dwOldProtect = 0;
	BOOL bRetVal = FALSE;

	// 修改目标页属性
	if (VirtualProtect(pAddr, sizeof(ULONG), PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		// 修改目标地址处数据
		*(PUCHAR)pAddr = uChar;
		// 恢复页属性
		bRetVal = VirtualProtect(pAddr, sizeof(ULONG), dwOldProtect, &dwOldProtect);
	}

	return bRetVal;
}

VOID __stdcall RevokeMsg3_0_0_47(lpwxstring Revokewxstring, PVOID unkowninfo1)
{
	PVOID unkowninfo1_temp =  unkowninfo1;

	// CString strRevokeMsg;
	if (Revokewxstring->data != NULL)
	{
		// 别人的撤回
		if (*(PDWORD(unkowninfo1_temp) + 13) == 0)
		{
			CString strRevokeMsg;
			LPWSTR tmp = Revokewxstring->data;
	
			strRevokeMsg.Format(L"%s, %s", tmp, L" 但是被无情的阻止了");
			MyAttW(L"消息是%s", strRevokeMsg);

			LPWSTR lpRevokeStringReplace = (LPWSTR)UtlAlloc((strRevokeMsg.GetLength() + 2) * 2);
			memset(lpRevokeStringReplace, 0, (strRevokeMsg.GetLength() + 2) * 2);
			memcpy(lpRevokeStringReplace, strRevokeMsg.GetString(), (strRevokeMsg.GetLength() + 2) * 2);

			UtlFree(Revokewxstring->data);

			Revokewxstring->data = lpRevokeStringReplace;
			Revokewxstring->len = strRevokeMsg.GetLength();
			Revokewxstring->maxlen = (strRevokeMsg.GetLength() / 0x10 + 1) * 0x10;
	
			// 3_0_0_47
			if (MAKELONG(47, 0) == WeChatCore::Instance()->m_wechatwin_lsver &&
				MAKELONG(0, 3) == WeChatCore::Instance()->m_wechatwin_msver)
			{
				PatchMemoryUCHAR(PVOID(0x79A99CC1 - 0x797C0000 + (ULONG_PTR)WeChatCore::Instance()->m_hModule), 0x75);
			}

		}

		// 自己的撤回,就不管了
		else
		{
			// 这里采取硬编码,特征就是一个了
			// 3_0_0_47
			if (MAKELONG(47, 0) == WeChatCore::Instance()->m_wechatwin_lsver &&
				MAKELONG(0, 3) == WeChatCore::Instance()->m_wechatwin_msver)
			{
				PatchMemoryUCHAR(PVOID(0x79A99CC1 - 0x797C0000 + (ULONG_PTR)WeChatCore::Instance()->m_hModule), 0x74);
			}

		}
	}
	return;
}

BOOL SetHook(PVOID pRelFunction, PVOID pMyFunction)
{
	BOOL bRetVal = FALSE;

	// jmp pMyFunction
	// 机器码位：e9 _dwOffset(跳转偏移)
	//          addr1 --> jmp _dwNewAddress指令的下一条指令的地址，即eip的值
	//          addr2 --> 跳转地址的值，即_dwNewAddress的值
	//          跳转偏移 _dwOffset = addr2 - addr1
	BYTE g_NewCode[5] = { 0xE9 };
	// 2. 保存原始指令5个字节
	memcpy(g_RelCode, pRelFunction, 5);
	// 3. 计算跳转偏移，构建跳转 newcode[5]
	// 跳转偏移  = 目标地址 - 指令所在- 指令长度
	DWORD dwOffset = (DWORD)pMyFunction - (DWORD)pRelFunction - 5;
	*(DWORD*)(g_NewCode + 1) = dwOffset;

	// 4. 写入跳转偏移
	// 修改目标页属性
	DWORD dwOldProtect;
	if (VirtualProtect(pRelFunction, sizeof(g_NewCode), PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		// 修改MessageBoxW指令前5个字节
		memcpy(pRelFunction, g_NewCode, sizeof(g_NewCode));
		// 恢复页属性
		bRetVal = VirtualProtect(pRelFunction, sizeof(g_NewCode), dwOldProtect, &dwOldProtect);
	}

	return bRetVal;
}

BOOL __stdcall UnHook(PVOID pRelFunction)
{
	BOOL bRetVal = FALSE;

	// 2.还原指令前5字节
	// 修改目标页属性
	DWORD dwOldProtect;
	if (VirtualProtect(pRelFunction, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		// 修改函数指令前5个字节
		memcpy(pRelFunction, g_RelCode, 5);

		// 恢复页属性
		bRetVal = VirtualProtect(pRelFunction, 12, dwOldProtect, &dwOldProtect);
	}

	if (bRetVal)
	{
		HookTStatus = FALSE;
	}

	return bRetVal;
}

__declspec(naked) VOID __stdcall RevokeMsg3_0_0_47Stub()
{
	// Pre
	__asm
	{
		PUSHAD;
		sub esp, 20;
	}

	__asm
	{
		mov  ebx, [esp + 0x14 + 0x20 + 4];
		push edx;   // 结构体指针
		push ebx;   // 字符串
		call RevokeMsg3_0_0_47;
		push RelTxRevokeMsg3_0_0_47;
		call UnHook;

	}

	// End
	__asm
	{
		add esp, 20;
		POPAD;
	}

	__asm
	{
		jmp RelTxRevokeMsg3_0_0_47;
	}
}

VOID WeChatCore::Start()
{

	//获取要注入的模块的基址
	m_hModule = GetModuleHandle(L"WECHATWIN.dll");
	if (!m_hModule)
	{
		MyAttW(L"[%s] 2s内没有找到 WECHATWIN \n", __FUNCTIONW__);
		return;
	}

	StartStatus = TRUE;

	MyAttW(L"[%s] WECHATWIN模块基址是%0x \n", __FUNCTIONW__, DWORD(m_hModule));

	StartImp();
}

VOID WeChatCore::StartImp()
{
	MyAttW(L"[%s] 开始搞事情......\n", __FUNCTIONW__);

	//获取要注入的模块的标准文件路径
	WCHAR lpFilename[MAX_PATH] = {};
	GetModuleFileName(m_hModule, lpFilename, MAX_PATH);
	//如果成功获取注入模块的版本信息
	if (GetPEVersion(lpFilename, &m_wechatwin_msver, &m_wechatwin_lsver))
	{
		// 获取模块代码段的大小和起始地址
		DWORD dwBaseOfCode = 0;
		DWORD CodeSectionSize = GetPECodeSectionSize((HMODULE)m_hModule, &dwBaseOfCode);

		// 针对3.0.0.47 直接点吧,不上特征码搜索,偷个懒,直接硬偏移了
		if (MAKELONG(47, 0) == WeChatCore::Instance()->m_wechatwin_lsver &&
			MAKELONG(0, 3) == WeChatCore::Instance()->m_wechatwin_msver)
		{
			
		} 

		unsigned char SigPatternRevoke3_0_0_47[102] ={
				0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0xCB, 0xCB, 0xCB, 0xCB, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00,
				0x50, 0x83, 0xEC, 0x08, 0x56, 0x57, 0xA1, 0xCB, 0xCB, 0xCB, 0xCB, 0x33, 0xC5, 0x50, 0x8D, 0x45,
				0xF4, 0x64, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xF2, 0x8B, 0xF9, 0x89, 0x7D, 0xF0, 0x8B, 0x45,
				0x08, 0x83, 0xEC, 0x14, 0x8B, 0xCC, 0x89, 0x65, 0xF0, 0xC7, 0x45, 0xEC, 0x00, 0x00, 0x00, 0x00,
				0x6A, 0xFF, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x41, 0x04, 0x00, 0x00, 0x00, 0x00, 0xC7,
				0x41, 0x08, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x41, 0x0C, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x41, 0x10,
				0x00, 0x00, 0x00, 0x00, 0xFF, 0x30
		};

		PVOID uPosRevoke3_0_0_47 = FastSearch((PVOID)((ULONG_PTR)m_hModule + dwBaseOfCode),
			CodeSectionSize, (PUCHAR)SigPatternRevoke3_0_0_47, 102);
		if (uPosRevoke3_0_0_47)
		{
			RelTxRevokeMsg3_0_0_47 = (TxRevokeMsg3_0_0_47)(DWORD(uPosRevoke3_0_0_47) + 0);
		}

		MyAttW(L"[%s] RelTxRevokeMsg3_0_0_47位置是%x", __FUNCTIONW__,
			(ULONG_PTR)RelTxRevokeMsg3_0_0_47);

		m_Init = TRUE;

	}

	if (m_Init)
	{
		// 开始执行Hook
		StartHook();
	}

	return;
}

VOID WeChatCore::StartHook()
{
	if (RelTxRevokeMsg3_0_0_47)
	{
		if (SetHook(RelTxRevokeMsg3_0_0_47, RevokeMsg3_0_0_47Stub))
		{
			HookTStatus = TRUE;			
		}
	}

	return;
}
