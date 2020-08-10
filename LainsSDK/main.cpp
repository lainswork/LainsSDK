#include "main.h"
#include "MemoryLoadDll.h"
#include "XorString.h"
#include "HardWare.h"
#include "md5.h"


//字符转换工具
namespace CHARTOOL
{
	//宽变窄
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
		delete[] pResult;//返回string防止出现内存泄漏
		return retStr;
	}
	//窄变宽
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
		delete[] pResult;//返回wstring防止出现内存泄漏
		return retStr;
	}
	//String转Wstring
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
	//Wstring转String
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
		delete[] pResult;//返回string防止出现内存泄漏
		return retStr;
	}
	//去掉字符串中的指定字符
	void Delete_chr(char* s, char ch)
	{
		char* t = s; //目标指针先指向原串头
		while (*s != '\0') //遍历字符串s
		{
			if (*s != ch) //如果当前字符不是要删除的，则保存到目标串中
				*t++ = *s;
			s++; //检查下一个字符
		}
		*t = '\0'; //置目标串结束符。
	}
	//Utf8转String
	std::string Utf8ToString(const std::string& str)
	{
		int nwLen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
		wchar_t* pwBuf = new wchar_t[nwLen + 1];    //一定要加1，不然会出现尾巴 
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
	//Utf8转String
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
	//String转Utf8
	std::string StringToUtf8(const std::string& str)
	{
		int nwLen = ::MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
		wchar_t* pwBuf = new wchar_t[nwLen + 1];    //一定要加1，不然会出现尾巴 
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
	//替换字串
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

//资源操作工具
namespace RESTOOL
{
	//分配相应大小的内存
	LPCH applyBuffer(IN SIZE_T size)
	{
		if (size <= 0) {
			printf("缓冲区大小不能小于0\r\n");
			return NULL;
		}

		//申请内存
		char* buffer = (char*)malloc(size);

		if (buffer == NULL) {
			printf("申请缓冲区失败!\r\n");
			return NULL;
		}

		//将指针填充为0
		memset(buffer, 0, size);



		return buffer;
	}
	//读取rc资源文件到内存
	BOOL readSource(IN HINSTANCE hinst, IN WORD sourecId, IN LPCCH sourceType, OUT LPVOID* p_buffer, OUT ULONG* size)
	{
		// 读取资源包文件 第二个参数时resource给定的IDR_STRUCT1,Struct是资源的类型名
		HRSRC hRsrc = FindResourceA(hinst, MAKEINTRESOURCEA(sourecId), sourceType);
		if (NULL == hRsrc) 
		{
			printf(xorstr("FindResourceA(hinst, MAKEINTRESOURCEA(sourecId), sourceType) FAIL\r\n").crypt_get());
			return FALSE;
		}

		//获取资源的大小
		*size = SizeofResource(hinst, hRsrc);
		if (0 == *size)
		{
			printf(xorstr("SizeofResource(hinst, hRsrc) FAIL\r\n").crypt_get());
			return FALSE;
		}
		//加载资源
		HGLOBAL hGlobal = LoadResource(hinst, hRsrc);
		if (NULL == hGlobal)
		{
			printf(xorstr("LoadResource(hinst, hRsrc)\r\n").crypt_get());
			return FALSE;
		}
		//锁定资源
		LPVOID pBuffer = LockResource(hGlobal);

		if (NULL == pBuffer) 
		{
			printf(xorstr("LockResource(hGlobal) FAIL\r\n").crypt_get());
			return FALSE;
		}


		//申请自己的缓冲区存贮资源
		*p_buffer = applyBuffer(*size);


		//将数据写入缓冲区
		memcpy(*p_buffer, pBuffer, *size);

		//TODO 解锁资源?
		GlobalUnlock(hGlobal);

		return true;
	}

}

//dll加载工具
namespace DLLTOOL 
{
	HMODULE GetSelfModuleHandle()
	{
		MEMORY_BASIC_INFORMATION mbi;
		return ((::VirtualQuery(GetSelfModuleHandle, &mbi, sizeof(mbi)) != 0) ? (HMODULE)mbi.AllocationBase : NULL);
	}

	//内存加载dll 传入存贮dll静态文件的内存指针和相应的数据
	bool MemoryLoadDll(IN PVOID* dllBuffer, IN ULONG* dllSize, OUT PVOID* imageBase) 
	{
		return MEMORYLOAD::MemoryLoadDll(dllBuffer, dllSize, imageBase);
	}
	//内存加载dll 直接传入rc资源文件
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
			printf(xorstr("RESTOOL::readSource:读取资源失败\r\n").crypt_get());
			return false;
		}
	}
	//通过序号或者函数名找到导出函数地址
	FARPROC WINAPI GetExportAddress(PVOID hMod, const char* lpProcName)
	{
		return MEMORYLOAD::GetExportAddress( hMod,lpProcName);
	}
	//远线程注入dll
	bool InjectDll(IN HANDLE hProcess, IN PVOID* dllBuffer, IN ULONG* dllSize, OUT PVOID* imageBase, bool is32bit) 
	{
		return MEMORYLOAD::MemoryLoadDllEx(hProcess, dllBuffer, dllSize, imageBase, is32bit);
	}
	//远线程注入dll
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
			printf(xorstr("RESTOOL::readSource:读取资源失败\r\n").crypt_get());
			return false;
		}
	}
}

//机器码生成工具
namespace MACTOOL
{
	//获取pc的机器特征码
	std::string GetMachineFeaturesCode()
	{
		return MD5(HardWare().strAllMacInfo).toString();
	}
	//获取网卡原生MAC地址
	std::string GetNetMacAdress()
	{
		std::string retStr = HardWare().strNetwork;
		return retStr;
	}
	//获取硬盘序列号
	std::string GetDiskDriveSerialNumber()
	{
		std::string retStr = HardWare().strNetwork;
		return retStr;
	}
	// 获取主板序列号
	std::string GetBaseBoardSerialNumber()
	{
		std::string retStr = HardWare().strBaseBoard;
		return retStr;
	}
	// 获取处理器ID
	std::string GetProcessorID()
	{
		std::string retStr = HardWare().strProcessorID;
		return retStr;
	}
	// 获取BIOS序列号
	std::string GetBaseBiosSerialNumber()
	{
		std::string retStr = HardWare().strBIOS;
		return retStr;
	}
	// 获取主板型号
	std::string GetBaseBoardType()
	{
		std::string retStr = HardWare().strBaseBoardType;
		return retStr;
	}
	// 获取网卡当前MAC地址
	std::string GetCurrentNetMacAdress()
	{
		std::string retStr = HardWare().strCurrentNetwork;
		return retStr;
	}
}

namespace MD5TOOL
{
	//生成字串的md5
	std::string MakeMd5(std::string str)
	{
		return MD5(str).toString();
	}
	//生成某块数据的md5
	std::string MakeMd5(const void* input, size_t length)
	{
		return MD5(input, length).toString();
	}
}