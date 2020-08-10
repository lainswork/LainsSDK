#include "main.h"



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
		::MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), pwBuf, nwLen);
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
}