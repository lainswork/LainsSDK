#include "main.h"
#include "MemoryLoadDll.h"
#include "XorString.h"
#include "HardWare.h"
#include "md5.h"


//�ַ�ת������
namespace CHARTOOL
{
	//���խ
	std::string UnicodeToAnsi(const wchar_t* szStr)
	{
		int nLen = WideCharToMultiByte(CP_ACP, 0, szStr, -1, NULL, 0, NULL, NULL);
		if (nLen == 0)
		{
			return NULL;
		}
		char* pResult = new char[nLen];
		WideCharToMultiByte(CP_ACP, 0, szStr, -1, pResult, nLen, NULL, NULL);
		std::string retStr(pResult);
		delete[] pResult;//����string��ֹ�����ڴ�й©
		return retStr;
	}
	//խ���
	std::wstring AnsiToUnicode(const char* szStr)
	{
		int nLen = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szStr, -1, NULL, 0);
		if (nLen == 0)
		{
			return NULL;
		}
		wchar_t* pResult = new wchar_t[nLen];
		MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szStr, -1, pResult, nLen);
		std::wstring retStr(pResult);
		delete[] pResult;//����wstring��ֹ�����ڴ�й©
		return retStr;
	}
	//StringתWstring
	std::wstring StringToWstring(const std::string& s)
	{
		int len;
		int slength = (int)s.length() + 1;
		len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
		wchar_t* buf = new wchar_t[len];
		MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
		std::wstring r(buf);
		delete[] buf;
		return r;
	}
	//WstringתString
	std::string WstringToString(const std::wstring& s)
	{
		int nLen = WideCharToMultiByte(CP_ACP, 0, s.c_str(), -1, NULL, 0, NULL, NULL);
		if (nLen == 0)
		{
			return NULL;
		}
		char* pResult = new char[nLen];
		WideCharToMultiByte(CP_ACP, 0, s.c_str(), -1, pResult, nLen, NULL, NULL);
		std::string retStr(pResult);
		delete[] pResult;//����string��ֹ�����ڴ�й©
		return retStr;
	}
	//ȥ���ַ����е�ָ���ַ�
	void Delete_chr(char* s, char ch)
	{
		char* t = s; //Ŀ��ָ����ָ��ԭ��ͷ
		while (*s != '\0') //�����ַ���s
		{
			if (*s != ch) //�����ǰ�ַ�����Ҫɾ���ģ��򱣴浽Ŀ�괮��
				*t++ = *s;
			s++; //�����һ���ַ�
		}
		*t = '\0'; //��Ŀ�괮��������
	}
	//Utf8תString
	std::string Utf8ToString(const std::string& str)
	{
		int nwLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
		wchar_t* pwBuf = new wchar_t[nwLen + 1];    //һ��Ҫ��1����Ȼ�����β�� 
		memset(pwBuf, 0, nwLen * 2 + 2);
		MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.length(), pwBuf, nwLen);
		int nLen = WideCharToMultiByte(CP_ACP, 0, pwBuf, -1, NULL, NULL, NULL, NULL);
		char* pBuf = new char[nLen + 1];
		memset(pBuf, 0, nLen + 1);
		WideCharToMultiByte(CP_ACP, 0, pwBuf, nwLen, pBuf, nLen, NULL, NULL);

		std::string strRet = pBuf;

		delete[]pBuf;
		delete[]pwBuf;
		pBuf = NULL;
		pwBuf = NULL;

		return strRet;
	}
	//Utf8תString
	std::string Utf8ToString(char* szCode)
	{
		std::string strRet = "";
		for (int i = 0; i < 4; i++)
		{
			if (szCode[i] >= '0' && szCode[i] <= '9')	continue;
			if (szCode[i] >= 'A' && szCode[i] <= 'F')	continue;
			if (szCode[i] >= 'a' && szCode[i] <= 'f')	continue;
			return strRet;
		}

		char unicode_hex[5] = { 0 };
		memcpy(unicode_hex, szCode, 4);
		unsigned int iCode = 0;
		sscanf_s(unicode_hex, "%04x", &iCode);
		wchar_t wchChar[4] = { 0 };
		wchChar[0] = iCode;

		char szAnsi[8] = { 0 };
		WideCharToMultiByte(CP_ACP, NULL, wchChar, 1, szAnsi, sizeof(szAnsi), NULL, NULL);
		strRet = std::string(szAnsi);

		return strRet;
	}
	//StringתUtf8
	std::string StringToUtf8(const std::string& str)
	{
		int nwLen = ::MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
		wchar_t* pwBuf = new wchar_t[nwLen + 1];    //һ��Ҫ��1����Ȼ�����β�� 
		ZeroMemory(pwBuf, nwLen * 2 + 2);
		::MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), pwBuf, (int)nwLen);
		int nLen = ::WideCharToMultiByte(CP_UTF8, 0, pwBuf, -1, NULL, NULL, NULL, NULL);
		char* pBuf = new char[nLen + 1];
		ZeroMemory(pBuf, nLen + 1);
		::WideCharToMultiByte(CP_UTF8, 0, pwBuf, nwLen, pBuf, nLen, NULL, NULL);

		std::string strRet(pBuf);

		delete[]pwBuf;
		delete[]pBuf;
		pwBuf = NULL;
		pBuf = NULL;

		return strRet;
	
	}
	//�滻�ִ�
	std::string& replace_all(std::string& str, const std::string& old_value, const std::string& new_value)
	{
		while (true)
		{
			std::string::size_type   pos(0);
			if ((pos = str.find(old_value)) != std::string::npos)
				str.replace(pos, old_value.length(), new_value);
			else   break;
		}
		return   str;
	}
}

//��Դ��������
namespace RESTOOL
{
	//������Ӧ��С���ڴ�
	LPCH applyBuffer(IN SIZE_T size)
	{
		if (size <= 0) {
			printf("��������С����С��0\r\n");
			return NULL;
		}

		//�����ڴ�
		char* buffer = (char*)malloc(size);

		if (buffer == NULL) {
			printf("���뻺����ʧ��!\r\n");
			return NULL;
		}

		//��ָ�����Ϊ0
		memset(buffer, 0, size);



		return buffer;
	}
	//��ȡrc��Դ�ļ����ڴ�
	BOOL readSource(IN HINSTANCE hinst, IN WORD sourecId, IN LPCCH sourceType, OUT LPVOID* p_buffer, OUT ULONG* size)
	{
		// ��ȡ��Դ���ļ� �ڶ�������ʱresource������IDR_STRUCT1,Struct����Դ��������
		HRSRC hRsrc = FindResourceA(hinst, MAKEINTRESOURCEA(sourecId), sourceType);
		if (NULL == hRsrc) 
		{
			printf(xorstr("FindResourceA(hinst, MAKEINTRESOURCEA(sourecId), sourceType) FAIL\r\n").crypt_get());
			return FALSE;
		}

		//��ȡ��Դ�Ĵ�С
		*size = SizeofResource(hinst, hRsrc);
		if (0 == *size)
		{
			printf(xorstr("SizeofResource(hinst, hRsrc) FAIL\r\n").crypt_get());
			return FALSE;
		}
		//������Դ
		HGLOBAL hGlobal = LoadResource(hinst, hRsrc);
		if (NULL == hGlobal)
		{
			printf(xorstr("LoadResource(hinst, hRsrc)\r\n").crypt_get());
			return FALSE;
		}
		//������Դ
		LPVOID pBuffer = LockResource(hGlobal);

		if (NULL == pBuffer) 
		{
			printf(xorstr("LockResource(hGlobal) FAIL\r\n").crypt_get());
			return FALSE;
		}


		//�����Լ��Ļ�����������Դ
		*p_buffer = applyBuffer(*size);


		//������д�뻺����
		memcpy(*p_buffer, pBuffer, *size);

		//TODO ������Դ?
		GlobalUnlock(hGlobal);

		return true;
	}

}

//dll���ع���
namespace DLLTOOL 
{
	HMODULE GetSelfModuleHandle()
	{
		MEMORY_BASIC_INFORMATION mbi;
		return ((::VirtualQuery(GetSelfModuleHandle, &mbi, sizeof(mbi)) != 0) ? (HMODULE)mbi.AllocationBase : NULL);
	}

	//�ڴ����dll �������dll��̬�ļ����ڴ�ָ�����Ӧ������
	bool MemoryLoadDll(IN PVOID* dllBuffer, IN ULONG* dllSize, OUT PVOID* imageBase) 
	{
		return MEMORYLOAD::MemoryLoadDll(dllBuffer, dllSize, imageBase);
	}
	//�ڴ����dll ֱ�Ӵ���rc��Դ�ļ�
	bool MemoryLoadDllEx(IN WORD sourecId, IN LPCCH sourceType)
	{
		PVOID Dll_buffer = 0;
		ULONG Dll_szie = 0;
		PVOID pDLL = 0;
		if (RESTOOL::readSource(GetSelfModuleHandle(), sourecId, sourceType, &Dll_buffer, &Dll_szie))
		{
			return MEMORYLOAD::MemoryLoadDll(&Dll_buffer, (ULONG*)&Dll_szie, &pDLL);
		}
		else
		{
			printf(xorstr("RESTOOL::readSource:��ȡ��Դʧ��\r\n").crypt_get());
			return false;
		}
	}
	//ͨ����Ż��ߺ������ҵ�����������ַ
	FARPROC WINAPI GetExportAddress(PVOID hMod, const char* lpProcName)
	{
		return MEMORYLOAD::GetExportAddress( hMod,lpProcName);
	}
	//Զ�߳�ע��dll
	bool InjectDll(IN HANDLE hProcess, IN PVOID* dllBuffer, IN ULONG* dllSize, OUT PVOID* imageBase, bool is32bit) 
	{
		return MEMORYLOAD::MemoryLoadDllEx(hProcess, dllBuffer, dllSize, imageBase, is32bit);
	}
	//Զ�߳�ע��dll
	bool InjectDllEx(IN HANDLE hProcess,IN WORD sourecId, IN LPCCH sourceType, bool is32bit)
	{
		PVOID Dll_buffer = 0;
		ULONG Dll_szie = 0;
		PVOID pDLL = 0;
		if (RESTOOL::readSource(GetSelfModuleHandle(), sourecId, sourceType, &Dll_buffer, &Dll_szie))
		{
			return MEMORYLOAD::MemoryLoadDllEx(hProcess, &Dll_buffer, (ULONG*)&Dll_szie, &pDLL, is32bit);
		}
		else
		{
			printf(xorstr("RESTOOL::readSource:��ȡ��Դʧ��\r\n").crypt_get());
			return false;
		}
	}
}

//���������ɹ���
namespace MACTOOL
{
	//��ȡpc�Ļ���������
	std::string GetMachineFeaturesCode()
	{
		return MD5(HardWare().strAllMacInfo).toString();
	}
	//��ȡ����ԭ��MAC��ַ
	std::string GetNetMacAdress()
	{
		std::string retStr = HardWare().strNetwork;
		return retStr;
	}
	//��ȡӲ�����к�
	std::string GetDiskDriveSerialNumber()
	{
		std::string retStr = HardWare().strNetwork;
		return retStr;
	}
	// ��ȡ�������к�
	std::string GetBaseBoardSerialNumber()
	{
		std::string retStr = HardWare().strBaseBoard;
		return retStr;
	}
	// ��ȡ������ID
	std::string GetProcessorID()
	{
		std::string retStr = HardWare().strProcessorID;
		return retStr;
	}
	// ��ȡBIOS���к�
	std::string GetBaseBiosSerialNumber()
	{
		std::string retStr = HardWare().strBIOS;
		return retStr;
	}
	// ��ȡ�����ͺ�
	std::string GetBaseBoardType()
	{
		std::string retStr = HardWare().strBaseBoardType;
		return retStr;
	}
	// ��ȡ������ǰMAC��ַ
	std::string GetCurrentNetMacAdress()
	{
		std::string retStr = HardWare().strCurrentNetwork;
		return retStr;
	}
}

namespace MD5TOOL
{
	//�����ִ���md5
	std::string MakeMd5(std::string str)
	{
		return MD5(str).toString();
	}
	//����ĳ�����ݵ�md5
	std::string MakeMd5(const void* input, size_t length)
	{
		return MD5(input, length).toString();
	}
}