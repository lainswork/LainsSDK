#include "HardWare.h"


HardWare::HardWare() : m_pWbemSvc(nullptr), m_pWbemLoc(nullptr), m_pEnumClsObj(nullptr)
{
	//��ʼ��
	this->InitWmi();
	//��ȡ����ԭ��MAC��ַ
	this->GetSingleItemInfo("Win32_NetworkAdapter WHERE (MACAddress IS NOT NULL) AND (NOT (PNPDeviceID LIKE 'ROOT%'))",
		"PNPDeviceID",
		this->strNetwork);

	//��ȡӲ�����к�
	this->GetSingleItemInfo("Win32_DiskDrive WHERE (SerialNumber IS NOT NULL) AND (MediaType LIKE 'Fixed hard disk%')",
		"SerialNumber",
		this->strDiskDrive);

	//��ȡ�������к�
	this->GetSingleItemInfo("Win32_BaseBoard WHERE (SerialNumber IS NOT NULL)",
		"SerialNumber",
		this->strBaseBoard);

	//��ȡ������ID 
	this->GetSingleItemInfo("Win32_Processor WHERE (ProcessorId IS NOT NULL)",
		"ProcessorId",
		this->strProcessorID);

	//��ȡBIOS���к�
	this->GetSingleItemInfo("Win32_BIOS WHERE (SerialNumber IS NOT NULL)",
		"SerialNumber",
		this->strBIOS);

	//��ȡ�����ͺ�
	this->GetSingleItemInfo("Win32_BaseBoard WHERE (Product IS NOT NULL)",
		"Product",
		this->strBaseBoardType);

	//��ȡ������ǰMAC��ַ
	this->GetSingleItemInfo("Win32_NetworkAdapter WHERE (MACAddress IS NOT NULL) AND (NOT (PNPDeviceID LIKE 'ROOT%'))",
		"MACAddress",
		this->strCurrentNetwork);
	//���к����
	strAllMacInfo = strNetwork + strDiskDrive + strBaseBoard + strProcessorID + strBIOS + strBaseBoardType + strCurrentNetwork;

}
HardWare::~HardWare()
{
	m_pWbemSvc = NULL;
	m_pWbemLoc = NULL;
	m_pEnumClsObj = NULL;

	this->ReleaseWmi();
}
//��ʼ��WMI 
HRESULT HardWare::InitWmi()
{
	HRESULT hr;
	//һ����ʼ��COM���  
	//��ʼ��COM  
	hr = ::CoInitializeEx(0, COINIT_MULTITHREADED);
	if (SUCCEEDED(hr) || RPC_E_CHANGED_MODE == hr)
	{
		//���ý��̵İ�ȫ���𣬣�����COM���ʱ�ڳ�ʼ��COM֮��Ҫ����CoInitializeSecurity���ý��̰�ȫ���𣬷���ᱻϵͳʶ��Ϊ������  
		hr = CoInitializeSecurity(NULL,
			-1,
			NULL,
			NULL,
			RPC_C_AUTHN_LEVEL_PKT,
			RPC_C_IMP_LEVEL_IMPERSONATE,
			NULL,
			EOAC_NONE,
			NULL);
		//VERIFY(SUCCEEDED(hr));  

		//��������һ��WMI�����ռ�����  
		//����һ��CLSID_WbemLocator����  
		hr = CoCreateInstance(CLSID_WbemLocator,
			0,
			CLSCTX_INPROC_SERVER,
			IID_IWbemLocator,
			(LPVOID*)&m_pWbemLoc);
		//        VERIFY(SUCCEEDED(hr));  

				//ʹ��m_pWbemLoc���ӵ�"root\cimv2"������m_pWbemSvc��ָ��  
		hr = m_pWbemLoc->ConnectServer((PWCHAR)L"ROOT\\CIMV2",
			NULL,
			NULL,
			0,
			NULL,
			0,
			0,
			&m_pWbemSvc);
		//        VERIFY(SUCCEEDED(hr));  

				//��������WMI���ӵİ�ȫ��  
		hr = CoSetProxyBlanket((IUnknown*)m_pWbemSvc,
			RPC_C_AUTHN_WINNT,
			RPC_C_AUTHZ_NONE,
			NULL,
			RPC_C_AUTHN_LEVEL_CALL,
			RPC_C_IMP_LEVEL_IMPERSONATE,
			NULL,
			EOAC_NONE);
		//        VERIFY(SUCCEEDED(hr));  

	}
	return(hr);
}
//�ͷ� 
HRESULT HardWare::ReleaseWmi()
{
	HRESULT hr = CoInitialize(NULL);

	if (NULL != m_pWbemSvc)
	{
		hr = m_pWbemSvc->Release();
	}
	if (NULL != m_pWbemLoc)
	{
		hr = m_pWbemLoc->Release();
	}
	if (NULL != m_pEnumClsObj)
	{
		hr = m_pEnumClsObj->Release();
	}

	::CoUninitialize();

	return(hr);
}


//��ȡһ�����Ա
BOOL HardWare::GetSingleItemInfo(std::string ClassName, std::string ClassMember, std::string& chRetValue)
	{

		std::string query = "SELECT * FROM ";
		VARIANT vtProp;
		ULONG uReturn;
		HRESULT hr;
		BOOL bRet = FALSE;

		if (NULL != m_pWbemSvc)
		{
			//��ѯ��ClassName�е������ֶ�,���浽m_pEnumClsObj��  
			query += ClassName;
			hr = m_pWbemSvc->ExecQuery((BSTR)L"WQL", (BSTR)this->s_To_ws(query).c_str(), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
				0, &m_pEnumClsObj);
			if (SUCCEEDED(hr))
			{
				//��ʼ��vtPropֵ  
				VariantInit(&vtProp);
				uReturn = 0;

				//���شӵ�ǰλ����ĵ�һ������m_pWbemClsObj��  
				hr = m_pEnumClsObj->Next(WBEM_INFINITE, 1, &m_pWbemClsObj, &uReturn);
				if (SUCCEEDED(hr) && uReturn > 0)
				{
					//��m_pWbemClsObj���ҳ�ClassMember��ʶ�ĳ�Ա����ֵ,�����浽vtProp������  
					hr = m_pWbemClsObj->Get(this->s_To_ws(ClassMember).c_str(), 0, &vtProp, 0, 0);
					if (SUCCEEDED(hr))
					{
						VariantToString(&vtProp, chRetValue);
						VariantClear(&vtProp);//���vtProp  
						bRet = TRUE;
					}
				}
			}
		}
		if (NULL != m_pEnumClsObj)
		{
			hr = m_pEnumClsObj->Release();
			m_pEnumClsObj = NULL;
		}
		if (NULL != m_pWbemClsObj)
		{
			hr = m_pWbemClsObj->Release();
			m_pWbemClsObj = NULL;
		}
		return bRet;

	}
	//��ȡһ����Ķ����Ա
BOOL HardWare::GetGroupItemInfo(std::string ClassName, std::string ClassMember[], int n, std::string& chRetValue)
	{

		std::string query = "SELECT * FROM ";
		std::string result, info;
		VARIANT vtProp;
		ULONG uReturn;
		HRESULT hr;
		int i;
		BOOL bRet = FALSE;
		if (NULL != m_pWbemSvc)
		{
			query += ClassName;
			hr = m_pWbemSvc->ExecQuery((BSTR)L"WQL", (BSTR)this->s_To_ws(query).c_str(), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 0, &m_pEnumClsObj);
			if (SUCCEEDED(hr))
			{
				VariantInit(&vtProp); //��ʼ��vtProp����  
				if (m_pEnumClsObj)
				{
					Sleep(10);
					uReturn = 0;
					hr = m_pEnumClsObj->Next(WBEM_INFINITE, 1, &m_pWbemClsObj, &uReturn);
					if (SUCCEEDED(hr) && uReturn > 0)
					{
						for (i = 0; i < n; ++i)
						{
							hr = m_pWbemClsObj->Get(this->char_To_wstring(ClassMember[i].c_str()).c_str(), 0, &vtProp, 0, 0);
							if (SUCCEEDED(hr))
							{
								VariantToString(&vtProp, info);
								chRetValue += info + "\t";
								VariantClear(&vtProp);
								bRet = TRUE;
							}
						}
						chRetValue += "\r\n";
					}
				}
			}
		}

		if (NULL != m_pEnumClsObj)
		{
			hr = m_pEnumClsObj->Release();
			m_pEnumClsObj = NULL;
		}
		if (NULL != m_pWbemClsObj)
		{
			hr = m_pWbemClsObj->Release();
			m_pWbemClsObj = NULL;
		}
		return bRet;
	}
	//��Variant���͵ı���ת��ΪCString
void HardWare::VariantToString(const LPVARIANT pVar, std::string& chRetValue)
	{

		wchar_t* pBstr;
		BYTE HUGEP* pBuf;
		LONG low, high, i;
		HRESULT hr;

		switch (pVar->vt)
		{
		case VT_BSTR:
		{
			chRetValue = this->wchar_To_string((wchar_t*)pVar->bstrVal);
		}
		break;
		case VT_BOOL:
		{
			if (VARIANT_TRUE == pVar->boolVal)
				chRetValue = "��";
			else
				chRetValue = "��";
		}
		break;
		case VT_I4:
		{
			//chRetValue.Format(_T("%d"), pVar->lVal);
			char buffer[50] = { 0 };
			sprintf(buffer, "%d", pVar->lVal);
			chRetValue += buffer;
		}
		break;
		case VT_UI1:
		{
			//chRetValue.Format(_T("%d"), pVar->bVal);
			char buffer[50] = { 0 };
			sprintf(buffer, "%d", pVar->bVal);
			chRetValue += buffer;
		}
		break;
		case VT_UI4:
		{
			//chRetValue.Format(_T("%d"), pVar->ulVal);
			char buffer[50] = { 0 };
			sprintf(buffer, "%d", pVar->ulVal);
			chRetValue += buffer;
		}
		break;

		case VT_BSTR | VT_ARRAY:
		{

			hr = SafeArrayAccessData(pVar->parray, (void HUGEP**) & pBstr);
			hr = SafeArrayUnaccessData(pVar->parray);
			chRetValue = wchar_To_string(pBstr);

		}
		break;

		case VT_I4 | VT_ARRAY:
		{
			SafeArrayGetLBound(pVar->parray, 1, &low);
			SafeArrayGetUBound(pVar->parray, 1, &high);

			hr = SafeArrayAccessData(pVar->parray, (void HUGEP**) & pBuf);
			hr = SafeArrayUnaccessData(pVar->parray);
			std::string strTmp;
			high = min(high, MAX_PATH * 2 - 1);
			for (i = low; i <= high; ++i)
			{
				char buffer[50] = { 0 };
				sprintf(buffer, "%02X", pBuf[i]);
				chRetValue += strTmp;
			}
		}
		break;
		default:
			break;
		}
	}
	//����ת��
std::string HardWare::wchar_To_string(const wchar_t* wchar)
	{
		char* m_char;
		SIZE_T len = WideCharToMultiByte(CP_ACP, 0, wchar, wcslen(wchar), NULL, 0, NULL, NULL);
		m_char = new char[len + 1];
		WideCharToMultiByte(CP_ACP, 0, wchar, wcslen(wchar), m_char, len, NULL, NULL);
		m_char[len] = '\0';
		std::string retStr(m_char);
		delete[] m_char;
		return retStr;
	}
	//����ת��
std::wstring HardWare::char_To_wstring(const char* cchar)
	{
		//���ַ���ָ�� δ��ʼ��
		wchar_t* m_wchar;
		//��ȡת������ַ�����
		SIZE_T len = MultiByteToWideChar(CP_ACP, 0, cchar, strlen(cchar), NULL, 0);
		//�û�ȡ�ĳ���+1 newһ�����ַ���
		m_wchar = new wchar_t[len + 1];
		//ת�����ַ���
		MultiByteToWideChar(CP_ACP, 0, cchar, strlen(cchar), m_wchar, len);
		//��β����0
		m_wchar[len] = '\0';
		std::wstring retStr(m_wchar);
		delete[] m_wchar;
		return retStr;
	}
	//����ת��
std::wstring HardWare::s_To_ws(const std::string& s)
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
	//ȥ���ַ����е�ָ���ַ�
void HardWare::del_chr(char* s, char ch)
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