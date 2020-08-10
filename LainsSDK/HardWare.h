#pragma once
#include <WbemIdl.h>  
#include <iostream>  
#pragma  warning(disable:4996)
#pragma comment(lib,"WbemUuid.lib")
class HardWare
{
public:
	 HardWare();
	 ~HardWare();
	

public:
	// 所有序列号的组合
	std::string strAllMacInfo;
	// 网卡原生MAC地址
	std::string strNetwork;
	// 硬盘序列号
	std::string strDiskDrive;
	// 主板序列号 
	std::string strBaseBoard;
	// 处理器ID  
	std::string strProcessorID;
	// BIOS序列号
	std::string strBIOS;
	// 主板型号
	std::string strBaseBoardType;
	// 网卡当前MAC地址
	std::string strCurrentNetwork;

private:
	//初始化WMI 
	 HRESULT InitWmi();
	//释放 
	 HRESULT ReleaseWmi();
	
private:
	//获取一个类成员
	 BOOL GetSingleItemInfo(std::string ClassName, std::string ClassMember, std::string& chRetValue);
	//获取一个类的多个成员
	 BOOL GetGroupItemInfo(std::string ClassName, std::string ClassMember[], int n, std::string& chRetValue);
	//将Variant类型的变量转换为CString
	 void VariantToString(const LPVARIANT pVar, std::string& chRetValue);
	//编码转换
	 std::string wchar_To_string(const wchar_t* wchar);
	//编码转换
	 std::wstring char_To_wstring(const char* cchar);
	//编码转换
	 std::wstring s_To_ws(const std::string& s);
	//去掉字符串中的指定字符
	 void del_chr(char* s, char ch);

private:
	IEnumWbemClassObject* m_pEnumClsObj;
	IWbemClassObject* m_pWbemClsObj;
	IWbemServices* m_pWbemSvc;
	IWbemLocator* m_pWbemLoc;
};

