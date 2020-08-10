#pragma once
#include <windows.h>
#include <string>
#pragma  warning(disable:4996)
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
}

