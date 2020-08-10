#pragma once
#include <windows.h>
#include <string>

#pragma  warning(disable:4996)

//�ַ�ת������
namespace CHARTOOL
{
	//���խ
	std::string UnicodeToAnsi(const wchar_t* szStr);
	//խ���
	std::wstring AnsiToUnicode(const char* szStr);
	//StringתWstring
	std::wstring StringToWstring(const std::string& s);
	//WstringתString
	std::string WstringToString(const std::wstring& s);
	//ȥ���ַ����е�ָ���ַ�
	void Delete_chr(char* s, char ch);
	//Utf8תString
	std::string Utf8ToString(const std::string& str);
	//Utf8תString
	std::string Utf8ToString(char* szCode);
	//StringתUtf8
	std::string StringToUtf8(const std::string& str);
	//�滻�ִ�
	std::string& replace_all(std::string& str, const std::string& old_value, const std::string& new_value);

}

//��Դ��������
namespace RESTOOL
{
	//��ȡ��Դ���ڴ���
	BOOL readSource(IN HINSTANCE hinst, IN WORD sourecId, IN LPCCH sourceType, OUT LPVOID* p_buffer, OUT ULONG* size);
}

//dll���ع���
namespace DLLTOOL
{
	//�ڴ����dll �������dll��̬�ļ����ڴ�ָ�����Ӧ������
	bool MemoryLoadDll(IN PVOID* dllBuffer, IN ULONG* dllSize, OUT PVOID* imageBase);
	//�ڴ����dll ֱ�Ӵ���rc��Դ�ļ�
	bool MemoryLoadDllEx(IN WORD sourecId, IN LPCCH sourceType);
	//ͨ����Ż��ߺ������ҵ�����������ַ
	FARPROC WINAPI GetExportAddress(PVOID hMod, const char* lpProcName);
	//Զ�߳�ע��dll
	bool InjectDll(IN HANDLE hProcess, IN PVOID* dllBuffer, IN ULONG* dllSize, OUT PVOID* imageBase, bool is32bit);
	//Զ�߳�ע��dll
	bool InjectDllEx(IN HANDLE hProcess,IN WORD sourecId, IN LPCCH sourceType, bool is32bit);
}

//���������ɹ���
namespace MACTOOL
{
	//��ȡpc�Ļ���������
	std::string GetMachineFeaturesCode();
	//��ȡ����ԭ��MAC��ַ
	std::string GetNetMacAdress();
	//��ȡӲ�����к�
	std::string GetDiskDriveSerialNumber();
	// ��ȡ�������к�
	std::string GetBaseBoardSerialNumber();
	// ��ȡ������ID
	std::string GetProcessorID();
	// ��ȡBIOS���к�
	std::string GetBaseBiosSerialNumber();
	// ��ȡ�����ͺ�
	std::string GetBaseBoardType();
	// ��ȡ������ǰMAC��ַ
	std::string GetCurrentNetMacAdress();
}

namespace MD5TOOL
{
	//�����ִ���md5
	std::string MakeMd5(std::string str);
	//����ĳ�����ݵ�md5
	std::string MakeMd5(const void* input, size_t length);
}