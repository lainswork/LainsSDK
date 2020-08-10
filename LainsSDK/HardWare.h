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
	// �������кŵ����
	std::string strAllMacInfo;
	// ����ԭ��MAC��ַ
	std::string strNetwork;
	// Ӳ�����к�
	std::string strDiskDrive;
	// �������к� 
	std::string strBaseBoard;
	// ������ID  
	std::string strProcessorID;
	// BIOS���к�
	std::string strBIOS;
	// �����ͺ�
	std::string strBaseBoardType;
	// ������ǰMAC��ַ
	std::string strCurrentNetwork;

private:
	//��ʼ��WMI 
	 HRESULT InitWmi();
	//�ͷ� 
	 HRESULT ReleaseWmi();
	
private:
	//��ȡһ�����Ա
	 BOOL GetSingleItemInfo(std::string ClassName, std::string ClassMember, std::string& chRetValue);
	//��ȡһ����Ķ����Ա
	 BOOL GetGroupItemInfo(std::string ClassName, std::string ClassMember[], int n, std::string& chRetValue);
	//��Variant���͵ı���ת��ΪCString
	 void VariantToString(const LPVARIANT pVar, std::string& chRetValue);
	//����ת��
	 std::string wchar_To_string(const wchar_t* wchar);
	//����ת��
	 std::wstring char_To_wstring(const char* cchar);
	//����ת��
	 std::wstring s_To_ws(const std::string& s);
	//ȥ���ַ����е�ָ���ַ�
	 void del_chr(char* s, char ch);

private:
	IEnumWbemClassObject* m_pEnumClsObj;
	IWbemClassObject* m_pWbemClsObj;
	IWbemServices* m_pWbemSvc;
	IWbemLocator* m_pWbemLoc;
};

