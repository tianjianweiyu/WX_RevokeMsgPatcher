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

// Hook ������Ϣ��ԭ��
typedef VOID(_stdcall* TxRevokeMsg3_0_0_47)();
TxRevokeMsg3_0_0_47   RelTxRevokeMsg3_0_0_47 = NULL;

// ��ӡ��־��������
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
*  �� �� ���� GetPEVersion
*  ��    �ڣ� 2020/10/16
*  �������ͣ� BOOL
*  ��    ���� LPCWSTR path �ļ�·��
*  ��    ���� DWORD * msver �������汾��
*  ��    ���� DWORD * lsver ���մΰ汾��
*  ��    �ܣ� ��ȡָ���ļ��İ汾��Ϣ���ɹ�����TRUE,ʧ�ܷ���FALSE
*/
BOOL GetPEVersion(LPCWSTR path, DWORD *msver, DWORD *lsver)
{
	BOOL status = FALSE;
	PVOID info = NULL;
	DWORD handle = 0;
	VS_FIXEDFILEINFO* vsinfo = NULL;
	UINT vsinfolen = 0;
	//��ȡ�汾��Ϣ���ɹ����ذ汾��Ϣ�Ĵ�С��ʧ�ܷ���0
	DWORD infolen = GetFileVersionInfoSizeW(path, &handle);
	//����ɹ���ȡ�汾��Ϣ
	if (infolen)
	{
		//����ռ��Ű汾��Ϣ
		info = malloc(infolen);
		if (info)
		{
			//��ȡָ���ļ��İ汾��Ϣ��Դ
			if (GetFileVersionInfoW(path, handle, infolen, info))
			{
				//��ָ���İ汾��Ϣ��Դ�м���ָ���İ汾��Ϣ
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
*  �� �� ���� GetPECodeSectionSize
*  ��    �ڣ� 2020/10/17
*  �������ͣ� DWORD
*  ��    ���� HMODULE hDllBase ģ���ַ
*  ��    ���� LPDWORD pBaseOfCode ����ģ��������ʼ��ַ
*  ��    �ܣ� ��ȡָ��ģ�����ε���ʼ��ַ���С����Сͨ������ֵ��ã�ʧ��Ϊ0
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

// ������������
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
			// �ж�ָ���ַ�Ƿ���Ч
			// �����ָ���ڴ洦û�ж�ȡȨ�ޣ����ط���
			if (IsBadReadPtr((const void*)&cur[i + j], 1))
			{
				bBadPoint = TRUE;
				break;
			}

			// 0xCBλ�����ض�λ��ַ����Ϊ�ض�λ��ַÿ���������ܲ�һ��
			// ����ʹ��0xCB����ô�����
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

// �޸�ָ����ַ��һ�ֽڵ�����
static BOOL PatchMemoryUCHAR(
	__in const PVOID pAddr,
	__in const UCHAR uChar)
{
	DWORD dwOldProtect = 0;
	BOOL bRetVal = FALSE;

	// �޸�Ŀ��ҳ����
	if (VirtualProtect(pAddr, sizeof(ULONG), PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		// �޸�Ŀ���ַ������
		*(PUCHAR)pAddr = uChar;
		// �ָ�ҳ����
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
		// ���˵ĳ���
		if (*(PDWORD(unkowninfo1_temp) + 13) == 0)
		{
			CString strRevokeMsg;
			LPWSTR tmp = Revokewxstring->data;
	
			strRevokeMsg.Format(L"%s, %s", tmp, L" ���Ǳ��������ֹ��");
			MyAttW(L"��Ϣ��%s", strRevokeMsg);

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

		// �Լ��ĳ���,�Ͳ�����
		else
		{
			// �����ȡӲ����,��������һ����
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
	// ������λ��e9 _dwOffset(��תƫ��)
	//          addr1 --> jmp _dwNewAddressָ�����һ��ָ��ĵ�ַ����eip��ֵ
	//          addr2 --> ��ת��ַ��ֵ����_dwNewAddress��ֵ
	//          ��תƫ�� _dwOffset = addr2 - addr1
	BYTE g_NewCode[5] = { 0xE9 };
	// 2. ����ԭʼָ��5���ֽ�
	memcpy(g_RelCode, pRelFunction, 5);
	// 3. ������תƫ�ƣ�������ת newcode[5]
	// ��תƫ��  = Ŀ���ַ - ָ������- ָ���
	DWORD dwOffset = (DWORD)pMyFunction - (DWORD)pRelFunction - 5;
	*(DWORD*)(g_NewCode + 1) = dwOffset;

	// 4. д����תƫ��
	// �޸�Ŀ��ҳ����
	DWORD dwOldProtect;
	if (VirtualProtect(pRelFunction, sizeof(g_NewCode), PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		// �޸�MessageBoxWָ��ǰ5���ֽ�
		memcpy(pRelFunction, g_NewCode, sizeof(g_NewCode));
		// �ָ�ҳ����
		bRetVal = VirtualProtect(pRelFunction, sizeof(g_NewCode), dwOldProtect, &dwOldProtect);
	}

	return bRetVal;
}

BOOL __stdcall UnHook(PVOID pRelFunction)
{
	BOOL bRetVal = FALSE;

	// 2.��ԭָ��ǰ5�ֽ�
	// �޸�Ŀ��ҳ����
	DWORD dwOldProtect;
	if (VirtualProtect(pRelFunction, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		// �޸ĺ���ָ��ǰ5���ֽ�
		memcpy(pRelFunction, g_RelCode, 5);

		// �ָ�ҳ����
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
		push edx;   // �ṹ��ָ��
		push ebx;   // �ַ���
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

	//��ȡҪע���ģ��Ļ�ַ
	m_hModule = GetModuleHandle(L"WECHATWIN.dll");
	if (!m_hModule)
	{
		MyAttW(L"[%s] 2s��û���ҵ� WECHATWIN \n", __FUNCTIONW__);
		return;
	}

	StartStatus = TRUE;

	MyAttW(L"[%s] WECHATWINģ���ַ��%0x \n", __FUNCTIONW__, DWORD(m_hModule));

	StartImp();
}

VOID WeChatCore::StartImp()
{
	MyAttW(L"[%s] ��ʼ������......\n", __FUNCTIONW__);

	//��ȡҪע���ģ��ı�׼�ļ�·��
	WCHAR lpFilename[MAX_PATH] = {};
	GetModuleFileName(m_hModule, lpFilename, MAX_PATH);
	//����ɹ���ȡע��ģ��İ汾��Ϣ
	if (GetPEVersion(lpFilename, &m_wechatwin_msver, &m_wechatwin_lsver))
	{
		// ��ȡģ�����εĴ�С����ʼ��ַ
		DWORD dwBaseOfCode = 0;
		DWORD CodeSectionSize = GetPECodeSectionSize((HMODULE)m_hModule, &dwBaseOfCode);

		// ���3.0.0.47 ֱ�ӵ��,��������������,͵����,ֱ��Ӳƫ����
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

		MyAttW(L"[%s] RelTxRevokeMsg3_0_0_47λ����%x", __FUNCTIONW__,
			(ULONG_PTR)RelTxRevokeMsg3_0_0_47);

		m_Init = TRUE;

	}

	if (m_Init)
	{
		// ��ʼִ��Hook
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
