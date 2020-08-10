#pragma once
#include <windows.h>
#include <string>

#pragma  warning(disable:4996)

//字符转换工具
namespace CHARTOOL
{
	//宽变窄
	std::string UnicodeToAnsi(const wchar_t* szStr);
	//窄变宽
	std::wstring AnsiToUnicode(const char* szStr);
	//String转Wstring
	std::wstring StringToWstring(const std::string& s);
	//Wstring转String
	std::string WstringToString(const std::wstring& s);
	//去掉字符串中的指定字符
	void Delete_chr(char* s, char ch);
	//Utf8转String
	std::string Utf8ToString(const std::string& str);
	//Utf8转String
	std::string Utf8ToString(char* szCode);
	//String转Utf8
	std::string StringToUtf8(const std::string& str);
	//替换字串
	std::string& replace_all(std::string& str, const std::string& old_value, const std::string& new_value);

}

//资源操作工具
namespace RESTOOL
{
	//读取资源到内存中
	BOOL readSource(IN HINSTANCE hinst, IN WORD sourecId, IN LPCCH sourceType, OUT LPVOID* p_buffer, OUT ULONG* size);
}

//dll加载工具
namespace DLLTOOL
{
	//内存加载dll 传入存贮dll静态文件的内存指针和相应的数据
	bool MemoryLoadDll(IN PVOID* dllBuffer, IN ULONG* dllSize, OUT PVOID* imageBase);
	//内存加载dll 直接传入rc资源文件
	bool MemoryLoadDllEx(IN WORD sourecId, IN LPCCH sourceType);
	//通过序号或者函数名找到导出函数地址
	FARPROC WINAPI GetExportAddress(PVOID hMod, const char* lpProcName);
	//远线程注入dll
	bool InjectDll(IN HANDLE hProcess, IN PVOID* dllBuffer, IN ULONG* dllSize, OUT PVOID* imageBase, bool is32bit);
	//远线程注入dll
	bool InjectDllEx(IN HANDLE hProcess,IN WORD sourecId, IN LPCCH sourceType, bool is32bit);
}

//机器码生成工具
namespace MACTOOL
{
	//获取pc的机器特征码
	std::string GetMachineFeaturesCode();
	//获取网卡原生MAC地址
	std::string GetNetMacAdress();
	//获取硬盘序列号
	std::string GetDiskDriveSerialNumber();
	// 获取主板序列号
	std::string GetBaseBoardSerialNumber();
	// 获取处理器ID
	std::string GetProcessorID();
	// 获取BIOS序列号
	std::string GetBaseBiosSerialNumber();
	// 获取主板型号
	std::string GetBaseBoardType();
	// 获取网卡当前MAC地址
	std::string GetCurrentNetMacAdress();
}

namespace MD5TOOL
{
	//生成字串的md5
	std::string MakeMd5(std::string str);
	//生成某块数据的md5
	std::string MakeMd5(const void* input, size_t length);
}