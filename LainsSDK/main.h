#pragma once
#include <windows.h>
#include <string>
#pragma  warning(disable:4996)
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
}

