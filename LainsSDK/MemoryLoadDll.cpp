#include "MemoryLoadDll.h"
#include "XorString.h"

namespace MEMORYLOAD {
	GRAVITY_ENGINE_API bool MemoryLoadDll(IN PVOID* dllBuffer, IN ULONG* dllSize, OUT PVOID* imageBase) {
		if (*dllBuffer == NULL || *dllSize < 10) {
			return false;
		}

		HMODULE NTDLL = GetModuleHandleA(xorstr("ntdll").crypt_get());
		PARAMX param;
		RtlZeroMemory(&param, sizeof(PARAMX));
		param.lpFileData = *dllBuffer;
		param.DataLength = *dllSize;
		param.LdrGetProcedureAddress = (LdrGetProcedureAddressT)GetProcAddress(NTDLL, xorstr("LdrGetProcedureAddress").crypt_get());;
		param.dwNtAllocateVirtualMemory = (NtAllocateVirtualMemoryT)GetProcAddress(NTDLL, xorstr("NtAllocateVirtualMemory").crypt_get());
		param.pLdrLoadDll = (LdrLoadDllT)GetProcAddress(NTDLL, xorstr("LdrLoadDll").crypt_get());
		param.RtlInitAnsiString = (RtlInitAnsiStringT)GetProcAddress(NTDLL, xorstr("RtlInitAnsiString").crypt_get());
		param.RtlAnsiStringToUnicodeString = (RtlAnsiStringToUnicodeStringT)GetProcAddress(NTDLL, xorstr("RtlAnsiStringToUnicodeString").crypt_get());
		param.RtlFreeUnicodeString = (RtlFreeUnicodeStringT)GetProcAddress(NTDLL, xorstr("RtlFreeUnicodeString").crypt_get());
		MemLoadLibrary mll;
		
#ifdef _WIN64
		DWORD shellCodeSize = sizeof(MemLoadShellcode_x64);
		PVOID shellCodeBuffer = MemLoadShellcode_x64;
#else
		DWORD shellCodeSize = sizeof(MemLoadShellcode_x86);
		PVOID shellCodeBuffer = MemLoadShellcode_x86;
#endif
		mll = (MemLoadLibrary)VirtualAlloc(
			0,
			shellCodeSize,
			MEM_COMMIT,
			PAGE_EXECUTE_READWRITE);

		if (mll == NULL) {
			//LOGFMTI("�����ڴ�ʧ��");
			printf(xorstr("�����ڴ�ʧ��\n").crypt_get());
			return false;
		}
		memcpy(mll, shellCodeBuffer, shellCodeSize);
		*imageBase = (PVOID)mll(&param);
		return true;
	}

	GRAVITY_ENGINE_API bool MemoryLoadDllEx(IN HANDLE hProcess, IN PVOID* dllBuffer, IN ULONG* dllSize, OUT PVOID* imageBase, bool is32bit) 
	{
		if (*dllBuffer == NULL || *dllSize < 10 || hProcess == 0)
		{
			printf(xorstr("����У��ʧ��\n").crypt_get());
			return false;
		}

		//�ɵ�Ȩ��
		SIZE_T dWrited = 0;
		DWORD shellCodeSize = 0;
		PVOID shellCodeBuffer = 0;
		if (is32bit)
		{
			shellCodeSize   = sizeof(MemLoadShellcode_x86);
			shellCodeBuffer = MemLoadShellcode_x86;
		}
		else
		{
			shellCodeSize = sizeof(MemLoadShellcode_x64);
			shellCodeBuffer = MemLoadShellcode_x64;
		}
		HMODULE NTDLL = GetModuleHandleA(xorstr("ntdll").crypt_get());
		PARAMX param;
		RtlZeroMemory(&param, sizeof(PARAMX));
		param.lpFileData = *dllBuffer;
		param.DataLength = *dllSize;

		//��ȡĿ��ĵ��뺯��,���Լ���ntdll���ж�λ


		param.LdrGetProcedureAddress = (LdrGetProcedureAddressT)GetProcAddress(NTDLL, xorstr("LdrGetProcedureAddress").crypt_get());;
		param.dwNtAllocateVirtualMemory = (NtAllocateVirtualMemoryT)GetProcAddress(NTDLL, xorstr("NtAllocateVirtualMemory").crypt_get());
		param.pLdrLoadDll = (LdrLoadDllT)GetProcAddress(NTDLL, xorstr("LdrLoadDll").crypt_get());
		param.RtlInitAnsiString = (RtlInitAnsiStringT)GetProcAddress(NTDLL, xorstr("RtlInitAnsiString").crypt_get());
		param.RtlAnsiStringToUnicodeString = (RtlAnsiStringToUnicodeStringT)GetProcAddress(NTDLL, xorstr("RtlAnsiStringToUnicodeString").crypt_get());
		param.RtlFreeUnicodeString = (RtlFreeUnicodeStringT)GetProcAddress(NTDLL, xorstr("RtlFreeUnicodeString").crypt_get());


		//�����ڴ�,��shellcode��DLL����,�Ͳ������Ƶ�Ŀ�����
		//PBYTE  pAddress = (PBYTE)VirtualAllocEx(hProcess, 0, *dllSize + shellCodeSize + sizeof(PARAMX) + 0x100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//��ȫ���,��С���0x100
		//IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress, IN ULONG ZeroBits, IN OUT PULONG RegionSize, IN ULONG AllocationType, IN ULONG Protect
		PBYTE  pAddress = (PBYTE)VirtualAllocEx(
			hProcess,
			0,
			*dllSize + shellCodeSize + sizeof(PARAMX) + 0x100,
			//&dWrited,
			MEM_COMMIT,
			PAGE_EXECUTE_READWRITE);

		if (pAddress == NULL) {
			//LOGFMTI("�����ڴ�ʧ��");
			printf(xorstr("�����ڴ�ʧ��\n").crypt_get());
			
			return false;
		}
		//�޳���DLL���ݵĵ�ַ
		param.lpFileData = pAddress;
		//DLL����д�뵽Ŀ��
		//if (!WriteProcessMemory(hProcess, pAddress, *dllBuffer, *dllSize, &dWrited)) {
		if (!WriteProcessMemory(hProcess, pAddress, *dllBuffer, *dllSize, &dWrited)) {
			//LOGFMTI("DLL����д�뵽Ŀ��ʧ��");
			printf(xorstr("DLL����д�뵽Ŀ��ʧ��\n").crypt_get());
			return false;
		}
		//shellcodeд�뵽Ŀ��
		//if (!WriteProcessMemory(hProcess, pAddress + *dllSize, shellCodeBuffer, shellCodeSize, &dWrited)) {
		if (!WriteProcessMemory(hProcess, pAddress + *dllSize, shellCodeBuffer, shellCodeSize, &dWrited)) {
			//LOGFMTI("shellcodeд�뵽Ŀ��ʧ��");
			printf(xorstr("shellcodeд�뵽Ŀ��ʧ��\n").crypt_get());
			return false;
		}
		//����д�뵽Ŀ��
		//if (!WriteProcessMemory(hProcess, pAddress + *dllSize + shellCodeSize, &param, sizeof(PARAMX), &dWrited)) {
		if (!WriteProcessMemory(hProcess, pAddress + *dllSize + shellCodeSize, &param, sizeof(PARAMX), &dWrited)) {
			//LOGFMTI("����д�뵽Ŀ��ʧ��");
			printf(xorstr("����д�뵽Ŀ��ʧ��\n").crypt_get());
			return false;
		}

		//����ע���߳�=pAddress+ dllsize,����=pAddress + dllsize+ shellcodesize;
		HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)(pAddress + *dllSize), pAddress + *dllSize + shellCodeSize, 0, 0);
		if (hThread)
		{
			DWORD dExecCode = 0;
			//LOGFMTI("�ȴ�ע���߳�ִ�����....\n");
			printf(xorstr("�ȴ�ע���߳�ִ�����....\n").crypt_get());
			WaitForSingleObject(hThread, -1);
			GetExitCodeThread(hThread, &dExecCode);
#ifdef _WIN64

			printf(xorstr("ע�����.... 0x%llX\n").crypt_get(), dExecCode + (((DWORD64)pAddress >> 32) << 32));//�����64λ,�����ڴ�����ĵ�ַ���ۼ�,���Դ�����ע���ģ���ַ
			*imageBase = (PVOID)(dExecCode + (((DWORD64)pAddress >> 32) << 32));
#else
			//LOGFMTI("ע�����.... 0x%X\n", dExecCode);//�����32λע��,�����dExecCode=ע���ģ���ַ
			*imageBase = (PVOID)dExecCode;
#endif

		//�ͷŵ�������ڴ�
			VirtualFreeEx(hProcess, pAddress, 0, MEM_FREE);
			CloseHandle(hThread);
			CloseHandle(hProcess);

		}
		else 
		{
			printf(xorstr("ע��ʧ��!!").crypt_get());
			return false;
		}

		return true;
	}


	/// <summary>
	/// ͨ����Ż��ߺ������ҵ�����������ַ
	/// </summary>
	/// <param name="hModule"></param>
	/// <param name="lpProcName"></param>
	/// <returns></returns>
	GRAVITY_ENGINE_API FARPROC WINAPI GetExportAddress(PVOID hMod, const char* lpProcName)
	{
		char* pBaseAddress = (char*)hMod;

		IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pBaseAddress;
		IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(pBaseAddress + pDosHeader->e_lfanew);
		IMAGE_OPTIONAL_HEADER* pOptionalHeader = &pNtHeaders->OptionalHeader;
		IMAGE_DATA_DIRECTORY* pDataDirectory = (IMAGE_DATA_DIRECTORY*)(&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
		IMAGE_EXPORT_DIRECTORY* pExportDirectory = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddress + pDataDirectory->VirtualAddress);

		void** ppFunctions = (void**)(pBaseAddress + pExportDirectory->AddressOfFunctions);
		WORD* pOrdinals = (WORD*)(pBaseAddress + pExportDirectory->AddressOfNameOrdinals);
		ULONG* pNames = (ULONG*)(pBaseAddress + pExportDirectory->AddressOfNames);
		/* char **pNames = (char **)(pBaseAddress + pExportDirectory->AddressOfNames); /* */

		void* pAddress = NULL;


		DWORD i;

		if (((DWORD_PTR)lpProcName >> 16) == 0)
		{
			WORD ordinal = LOWORD(lpProcName);
			DWORD dwOrdinalBase = pExportDirectory->Base;

			if (ordinal < dwOrdinalBase || ordinal >= dwOrdinalBase + pExportDirectory->NumberOfFunctions) {
				return NULL;
			}


			pAddress = (FARPROC)(pBaseAddress + (DWORD_PTR)ppFunctions[ordinal - dwOrdinalBase]);
		}
		else
		{
			for (i = 0; i < pExportDirectory->NumberOfNames; i++)
			{
				char* szName = (char*)pBaseAddress + (DWORD_PTR)pNames[i];
				if (strcmp(lpProcName, szName) == 0)
				{
					pAddress = (FARPROC)(pBaseAddress + ((ULONG*)(pBaseAddress + pExportDirectory->AddressOfFunctions))[pOrdinals[i]]);
					break;
				}
			}
		}

		if ((char*)pAddress >= (char*)pExportDirectory && (char*)pAddress < (char*)pExportDirectory + pDataDirectory->Size)
		{
			char* szFunctionName;
			char szDllName[256] = { 0 };
			PVOID hForward;
			memcpy(szDllName, pAddress, strlen((char*)pAddress));

			if (!szDllName)
				return NULL;

			pAddress = NULL;
			szFunctionName = strchr(szDllName, '.');
			*szFunctionName++ = 0;

			hForward = (PVOID)LoadLibraryA(szDllName);
			printf(xorstr("%s������ϵͳģ��%s��,�����ҵ���,�ҵ��ĵ�ַ: %p").crypt_get(), lpProcName, szDllName, hForward);
			pAddress = GetExportAddress(hForward, szFunctionName);
		}

		return (FARPROC)pAddress;
	}


	//GRAVITY_ENGINE_API bool MemoryLoadDllExAPC(IN HANDLE hProcess, IN DWORD dwTid,IN PVOID* dllBuffer, IN ULONG* dllSize, OUT ULONG_PTR* imageBase) {
	//	if (*dllBuffer == NULL || *dllSize < 10 || hProcess == 0) {
	//		LOGFMTI("����У��ʧ��");
	//		return false;
	//	}
	//
	//	//�ɵ�Ȩ��
	//	SIZE_T dWrited = 0;
	//
	//#ifdef _WIN64
	//	DWORD shellCodeSize = sizeof(MemLoadShellcode_x64);
	//	PVOID shellCodeBuffer = MemLoadShellcode_x64;
	//#else
	//	DWORD shellCodeSize = sizeof(MemLoadShellcode_x86);
	//	PVOID shellCodeBuffer = MemLoadShellcode_x86;
	//#endif
	//
	//	HMODULE NTDLL = GetModuleHandleA("ntdll");
	//	PARAMX param;
	//	RtlZeroMemory(&param, sizeof(PARAMX));
	//	param.lpFileData = *dllBuffer;
	//	param.DataLength = *dllSize;
	//
	//	//��ȡĿ��ĵ��뺯��,���Լ���ntdll���ж�λ
	//
	//
	//	param.LdrGetProcedureAddress = (LdrGetProcedureAddressT)GetProcAddress(NTDLL, "LdrGetProcedureAddress");;
	//	param.dwNtAllocateVirtualMemory = (NtAllocateVirtualMemoryT)GetProcAddress(NTDLL, "NtAllocateVirtualMemory");
	//	param.pLdrLoadDll = (LdrLoadDllT)GetProcAddress(NTDLL, "LdrLoadDll");
	//	param.RtlInitAnsiString = (RtlInitAnsiStringT)GetProcAddress(NTDLL, "RtlInitAnsiString");
	//	param.RtlAnsiStringToUnicodeString = (RtlAnsiStringToUnicodeStringT)GetProcAddress(NTDLL, "RtlAnsiStringToUnicodeString");
	//	param.RtlFreeUnicodeString = (RtlFreeUnicodeStringT)GetProcAddress(NTDLL, "RtlFreeUnicodeString");
	//
	//
	//	//�����ڴ�,��shellcode��DLL����,�Ͳ������Ƶ�Ŀ�����
	//	//PBYTE  pAddress = (PBYTE)VirtualAllocEx(hProcess, 0, *dllSize + shellCodeSize + sizeof(PARAMX) + 0x100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//��ȫ���,��С���0x100
	//	//IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress, IN ULONG ZeroBits, IN OUT PULONG RegionSize, IN ULONG AllocationType, IN ULONG Protect
	//	PBYTE  pAddress = (PBYTE)NtAllocateVirtualMemory(
	//		hProcess,
	//		0,
	//		*dllSize + shellCodeSize + sizeof(PARAMX) + 0x100,
	//		&dWrited,
	//		MEM_COMMIT,
	//		PAGE_EXECUTE_READWRITE);
	//
	//	if (pAddress == NULL) {
	//		LOGFMTI("�����ڴ�ʧ��");
	//		return false;
	//	}
	//	//�޳���DLL���ݵĵ�ַ
	//	param.lpFileData = pAddress;
	//	//DLL����д�뵽Ŀ��
	//	//if (!WriteProcessMemory(hProcess, pAddress, *dllBuffer, *dllSize, &dWrited)) {
	//	if (!NtWriteVirtualMemory(hProcess, pAddress, *dllBuffer, *dllSize, &dWrited)) {
	//		LOGFMTI("DLL����д�뵽Ŀ��ʧ��");
	//		return false;
	//	}
	//	//shellcodeд�뵽Ŀ��
	//	//if (!WriteProcessMemory(hProcess, pAddress + *dllSize, shellCodeBuffer, shellCodeSize, &dWrited)) {
	//	if (!NtWriteVirtualMemory(hProcess, pAddress + *dllSize, shellCodeBuffer, shellCodeSize, &dWrited)) {
	//		LOGFMTI("shellcodeд�뵽Ŀ��ʧ��");
	//		return false;
	//	}
	//	//����д�뵽Ŀ��
	//	//if (!WriteProcessMemory(hProcess, pAddress + *dllSize + shellCodeSize, &param, sizeof(PARAMX), &dWrited)) {
	//	if (!NtWriteVirtualMemory(hProcess, pAddress + *dllSize + shellCodeSize, &param, sizeof(PARAMX), &dWrited)) {
	//		LOGFMTI("����д�뵽Ŀ��ʧ��");
	//		return false;
	//	}
	//
	////	//����ע���߳�=pAddress+ dllsize,����=pAddress + dllsize+ shellcodesize;
	////	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)(pAddress + *dllSize), pAddress + *dllSize + shellCodeSize, 0, 0);
	////	if (hThread)
	////	{
	////		DWORD dExecCode = 0;
	////		LOGFMTI("�ȴ�ע���߳�ִ�����....\n");
	////		WaitForSingleObject(hThread, -1);
	////		GetExitCodeThread(hThread, &dExecCode);
	////#ifdef _WIN64
	////
	////		LOGFMTI("ע�����.... 0x%llX\n", dExecCode + (((DWORD64)pAddress >> 32) << 32));//�����64λ,�����ڴ�����ĵ�ַ���ۼ�,���Դ�����ע���ģ���ַ
	////#else
	////		LOGFMTI("ע�����.... 0x%llX\n", dExecCode);//�����32λע��,�����dExecCode=ע���ģ���ַ
	////#endif
	////
	////		//�ͷŵ�������ڴ�
	////		VirtualFreeEx(hProcess, pAddress, 0, MEM_FREE);
	////		CloseHandle(hThread);
	////		CloseHandle(hProcess);
	////
	////	}
	////	else {
	////		LOGFMTI("ע��ʧ��!!");
	////		return false;
	////	}
	//
	//	
	//	//6.�����߳�Tid,���߳̾��
	//	HANDLE hThread = NULL;
	//	NtOpenThread(&hThread,THREAD_ALL_ACCESS, FALSE, dwTid);
	//	if (NULL == hThread)
	//	{
	//		return;
	//	}
	//	//7.��APC�����в���ص�����
	//	QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)lpAddr);
	//
	//	CloseHandle(hThread);
	//	CloseHandle(hProcess);
	//
	//	return true;
	//}



	//-------------------------dll load--------------------------------


	void ShowError(const char *lpszText)
	{
		char szErr[MAX_PATH] = { 0 };
		sprintf(szErr, xorstr("%s Error!\nError Code Is:%d\n").crypt_get(), lpszText, GetLastError());
#ifdef _DEBUG
		MessageBoxA(NULL, szErr, "ERROR", MB_OK | MB_ICONERROR);
#endif
	}



	// ģ��LoadLibrary�����ڴ�DLL�ļ���������
	// lpData: �ڴ�DLL�ļ����ݵĻ�ַ
	// dwSize: �ڴ�DLL�ļ����ڴ��С
	// ����ֵ: �ڴ�DLL���ص����̵ļ��ػ�ַ
	GRAVITY_ENGINE_API LPVOID MmLoadLibrary(LPVOID lpData, DWORD dwSize)
	{
		LPVOID lpBaseAddress = NULL;

		// ��ȡ�����С
		DWORD dwSizeOfImage = GetSizeOfImage(lpData);

		// �ڽ����п���һ���ɶ�����д����ִ�е��ڴ��
		lpBaseAddress = ::VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NULL == lpBaseAddress)
		{
			ShowError(xorstr("VirtualAlloc").crypt_get());
			return NULL;
		}
		::RtlZeroMemory(lpBaseAddress, dwSizeOfImage);

		// ���ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ���
		if (FALSE == MmMapFile(lpData, lpBaseAddress))
		{
			ShowError(xorstr("MmMapFile").crypt_get());
			return NULL;
		}

		// �޸�PE�ļ��ض�λ����Ϣ
		if (FALSE == DoRelocationTable(lpBaseAddress))
		{
			ShowError(xorstr("DoRelocationTable").crypt_get());
			return NULL;
		}

		// ��дPE�ļ��������Ϣ
		if (FALSE == DoImportTable(lpBaseAddress))
		{
			ShowError(xorstr("DoImportTable").crypt_get());
			return NULL;
		}

		//�޸�ҳ���ԡ�Ӧ�ø���ÿ��ҳ�����Ե����������Ӧ�ڴ�ҳ�����ԡ�
		//ͳһ���ó�һ������PAGE_EXECUTE_READWRITE
		DWORD dwOldProtect = 0;
		if (FALSE == ::VirtualProtect(lpBaseAddress, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			ShowError(xorstr("VirtualProtect").crypt_get());
			return NULL;
		}

		// �޸�PE�ļ����ػ�ַIMAGE_NT_HEADERS.OptionalHeader.ImageBase
		if (FALSE == SetImageBase(lpBaseAddress))
		{
			ShowError(xorstr("SetImageBase").crypt_get());
			return NULL;
		}

		// ����DLL����ں���DllMain,������ַ��ΪPE�ļ�����ڵ�IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
		if (FALSE == CallDllMain(lpBaseAddress))
		{
			ShowError(xorstr("CallDllMain").crypt_get());
			return NULL;
		}

		return lpBaseAddress;
	}



	//��ִ��dllmain
	GRAVITY_ENGINE_API LPVOID MmLoadLibraryNoCallDllMain(LPVOID lpData, DWORD dwSize)
	{
		LPVOID lpBaseAddress = NULL;

		// ��ȡ�����С
		DWORD dwSizeOfImage = GetSizeOfImage(lpData);

		// �ڽ����п���һ���ɶ�����д����ִ�е��ڴ��
		lpBaseAddress = ::VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NULL == lpBaseAddress)
		{
			ShowError("VirtualAlloc");
			return NULL;
		}
		::RtlZeroMemory(lpBaseAddress, dwSizeOfImage);

		// ���ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ���
		if (FALSE == MmMapFile(lpData, lpBaseAddress))
		{
			ShowError("MmMapFile");
			return NULL;
		}

		// �޸�PE�ļ��ض�λ����Ϣ
		if (FALSE == DoRelocationTable(lpBaseAddress))
		{
			ShowError("DoRelocationTable");
			return NULL;
		}

		// ��дPE�ļ��������Ϣ
		if (FALSE == DoImportTable(lpBaseAddress))
		{
			ShowError("DoImportTable");
			return NULL;
		}

		//�޸�ҳ���ԡ�Ӧ�ø���ÿ��ҳ�����Ե����������Ӧ�ڴ�ҳ�����ԡ�
		//ͳһ���ó�һ������PAGE_EXECUTE_READWRITE
		DWORD dwOldProtect = 0;
		if (FALSE == ::VirtualProtect(lpBaseAddress, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			ShowError("VirtualProtect");
			return NULL;
		}

		// �޸�PE�ļ����ػ�ַIMAGE_NT_HEADERS.OptionalHeader.ImageBase
		if (FALSE == SetImageBase(lpBaseAddress))
		{
			ShowError("SetImageBase");
			return NULL;
		}
		return lpBaseAddress;
	}


	// �ж��Ƿ����ض�λ�����
	GRAVITY_ENGINE_API BOOL IsExistRelocationTable(LPVOID lpBaseAddress)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((unsigned long)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		// �ж��Ƿ��� �ض�λ��
		if ((PVOID)pLoc == (PVOID)pDosHeader)
		{
			// �ض�λ�� Ϊ��
			return FALSE;
		}

		return TRUE;
	}


	// ģ��PE�����������ڴ�EXE�ļ���������
	// lpData: �ڴ�EXE�ļ����ݵĻ�ַ
	// dwSize: �ڴ�EXE�ļ����ڴ��С
	// ����ֵ: �ڴ�EXE���ص����̵ļ��ػ�ַ
	GRAVITY_ENGINE_API LPVOID MmLoadExe(LPVOID lpData, DWORD dwSize)
	{
		LPVOID lpBaseAddress = NULL;

		// ��ȡ�����С
		DWORD dwSizeOfImage = GetSizeOfImage(lpData);

		// �ڽ����п���һ���ɶ�����д����ִ�е��ڴ��
		lpBaseAddress = ::VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NULL == lpBaseAddress)
		{
			ShowError("VirtualAlloc");
			return NULL;
		}
		::RtlZeroMemory(lpBaseAddress, dwSizeOfImage);

		// ���ڴ�PE���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ���
		if (FALSE == MmMapFile(lpData, lpBaseAddress))
		{
			ShowError("MmMapFile");
			return NULL;
		}

		// �޸�PE�ļ��ض�λ����Ϣ
		if (FALSE == DoRelocationTable(lpBaseAddress))
		{
			ShowError("DoRelocationTable");
			return NULL;
		}

		// ��дPE�ļ��������Ϣ
		if (FALSE == DoImportTable(lpBaseAddress))
		{
			ShowError("DoImportTable");
			return NULL;
		}

		//�޸�ҳ���ԡ�Ӧ�ø���ÿ��ҳ�����Ե����������Ӧ�ڴ�ҳ�����ԡ�
		//ͳһ���ó�һ������PAGE_EXECUTE_READWRITE
		DWORD dwOldProtect = 0;
		if (FALSE == ::VirtualProtect(lpBaseAddress, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			ShowError("VirtualProtect");
			return NULL;
		}

		// �޸�PE�ļ����ػ�ַIMAGE_NT_HEADERS.OptionalHeader.ImageBase
		if (FALSE == SetImageBase(lpBaseAddress))
		{
			ShowError("SetImageBase");
			return NULL;
		}

		// ��ת��PE����ڵ㴦ִ��, ������ַ��ΪPE�ļ�����ڵ�IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
		if (FALSE == CallExeEntry(lpBaseAddress))
		{
			ShowError("CallExeEntry");
			return NULL;
		}

		return lpBaseAddress;
	}



	// ģ��PE�����������ڴ�EXE�ļ���������
	// lpData: �ڴ�EXE�ļ����ݵĻ�ַ
	// dwSize: �ڴ�EXE�ļ����ڴ��С
	// ����ֵ: �ڴ�EXE���ص����̵ļ��ػ�ַ
	GRAVITY_ENGINE_API LPVOID MmLoadExeNoCallMain(LPVOID lpData, DWORD dwSize)
	{
		LPVOID lpBaseAddress = NULL;

		// ��ȡ�����С
		DWORD dwSizeOfImage = GetSizeOfImage(lpData);

		// �ڽ����п���һ���ɶ�����д����ִ�е��ڴ��
		lpBaseAddress = ::VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NULL == lpBaseAddress)
		{
			ShowError("VirtualAlloc");
			return NULL;
		}
		::RtlZeroMemory(lpBaseAddress, dwSizeOfImage);

		// ���ڴ�PE���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ���
		if (FALSE == MmMapFile(lpData, lpBaseAddress))
		{
			ShowError("MmMapFile");
			return NULL;
		}

		// �޸�PE�ļ��ض�λ����Ϣ
		if (FALSE == DoRelocationTable(lpBaseAddress))
		{
			ShowError("DoRelocationTable");
			return NULL;
		}

		// ��дPE�ļ��������Ϣ
		if (FALSE == DoImportTable(lpBaseAddress))
		{
			ShowError("DoImportTable");
			return NULL;
		}

		//�޸�ҳ���ԡ�Ӧ�ø���ÿ��ҳ�����Ե����������Ӧ�ڴ�ҳ�����ԡ�
		//ͳһ���ó�һ������PAGE_EXECUTE_READWRITE
		DWORD dwOldProtect = 0;
		if (FALSE == ::VirtualProtect(lpBaseAddress, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			ShowError("VirtualProtect");
			return NULL;
		}

		// �޸�PE�ļ����ػ�ַIMAGE_NT_HEADERS.OptionalHeader.ImageBase
		if (FALSE == SetImageBase(lpBaseAddress))
		{
			ShowError("SetImageBase");
			return NULL;
		}

		return lpBaseAddress;
	}


	// ����PE�ṹ,��ȡPE�ļ����ص��ڴ��ľ����С
	// lpData: �ڴ�DLL�ļ����ݵĻ�ַ
	// ����ֵ: ����PE�ļ��ṹ��IMAGE_NT_HEADERS.OptionalHeader.SizeOfImageֵ�Ĵ�С
	GRAVITY_ENGINE_API ULONG_PTR GetSizeOfImage(LPVOID lpData)
	{
		ULONG_PTR dwSizeOfImage = 0;
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpData;
#ifdef _WIN64
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG64)pDosHeader + pDosHeader->e_lfanew);
#else
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
#endif

		dwSizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;

		return dwSizeOfImage;
	}


	// ���ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ���
	// lpData: �ڴ�DLL�ļ����ݵĻ�ַ
	// lpBaseAddress: �ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ
	// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE
	GRAVITY_ENGINE_API BOOL MmMapFile(LPVOID lpData, LPVOID lpBaseAddress)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpData;
#ifdef _WIN64
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG64)pDosHeader + pDosHeader->e_lfanew);
		// ��ȡSizeOfHeaders��ֵ: ����ͷ+�ڱ�ͷ�Ĵ�С
		DWORD dwSizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
		// ��ȡ�ڱ������
		WORD wNumberOfSections = pNtHeaders->FileHeader.NumberOfSections;
		// ��ȡ��һ���ڱ�ͷ�ĵ�ַ
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONGLONG)pNtHeaders + sizeof(IMAGE_NT_HEADERS));

		// ���� ����ͷ+�ڱ�ͷ�Ĵ�С
		::RtlCopyMemory(lpBaseAddress, lpData, dwSizeOfHeaders);
		// ����SectionAlignmentѭ�����ؽڱ�
		WORD i = 0;
		LPVOID lpSrcMem = NULL;
		LPVOID lpDestMem = NULL;
		DWORD dwSizeOfRawData = 0;
		for (i = 0; i < wNumberOfSections; i++)
		{
			if ((0 == pSectionHeader->VirtualAddress) ||
				(0 == pSectionHeader->SizeOfRawData))
			{
				pSectionHeader++;
				continue;
			}

			lpSrcMem = (LPVOID)((ULONGLONG)lpData + pSectionHeader->PointerToRawData);
			lpDestMem = (LPVOID)((ULONGLONG)lpBaseAddress + pSectionHeader->VirtualAddress);
			dwSizeOfRawData = pSectionHeader->SizeOfRawData;
			::RtlCopyMemory(lpDestMem, lpSrcMem, dwSizeOfRawData);

			pSectionHeader++;
		}
#else
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		// ��ȡSizeOfHeaders��ֵ: ����ͷ+�ڱ�ͷ�Ĵ�С
		DWORD dwSizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
		// ��ȡ�ڱ������
		WORD wNumberOfSections = pNtHeaders->FileHeader.NumberOfSections;
		// ��ȡ��һ���ڱ�ͷ�ĵ�ַ
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(IMAGE_NT_HEADERS));

		// ���� ����ͷ+�ڱ�ͷ�Ĵ�С
		::RtlCopyMemory(lpBaseAddress, lpData, dwSizeOfHeaders);
		// ����SectionAlignmentѭ�����ؽڱ�
		WORD i = 0;
		LPVOID lpSrcMem = NULL;
		LPVOID lpDestMem = NULL;
		DWORD dwSizeOfRawData = 0;
		for (i = 0; i < wNumberOfSections; i++)
		{
			if ((0 == pSectionHeader->VirtualAddress) ||
				(0 == pSectionHeader->SizeOfRawData))
			{
				pSectionHeader++;
				continue;
			}

			lpSrcMem = (LPVOID)((DWORD)lpData + pSectionHeader->PointerToRawData);
			lpDestMem = (LPVOID)((DWORD)lpBaseAddress + pSectionHeader->VirtualAddress);
			dwSizeOfRawData = pSectionHeader->SizeOfRawData;
			::RtlCopyMemory(lpDestMem, lpSrcMem, dwSizeOfRawData);

			pSectionHeader++;
		}
#endif



		return TRUE;
	}


	// ����SectionAlignment
	// dwSize: ��ʾδ����ǰ�ڴ�Ĵ�С
	// dwAlignment: �����Сֵ
	// ����ֵ: �����ڴ����֮���ֵ
	GRAVITY_ENGINE_API ULONG_PTR Align(ULONG_PTR dwSize, ULONG_PTR dwAlignment)
	{
		ULONG_PTR dwRet = 0;
		ULONG_PTR i = 0, j = 0;
		i = dwSize / dwAlignment;
		j = dwSize % dwAlignment;
		if (0 != j)
		{
			i++;
		}

		dwRet = i * dwAlignment;

		return dwRet;
	}


	// �޸�PE�ļ��ض�λ����Ϣ
	// lpBaseAddress: �ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ
	// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE
	GRAVITY_ENGINE_API BOOL DoRelocationTable(LPVOID lpBaseAddress)
	{
		/* �ض�λ��Ľṹ��
		// DWORD sectionAddress, DWORD size (����������Ҫ�ض�λ������)
		// ���� 1000����Ҫ����5���ض�λ���ݵĻ����ض�λ���������
		// 00 10 00 00   14 00 00 00      xxxx xxxx xxxx xxxx xxxx 0000
		// -----------   -----------      ----
		// �����ڵ�ƫ��  �ܳߴ�=8+6*2     ��Ҫ�����ĵ�ַ           ���ڶ���4�ֽ�
		// �ض�λ�������ɸ����������address �� size����0 ��ʾ����
		// ��Ҫ�����ĵ�ַ��12λ�ģ���4λ����̬�֣�intel cpu����3
		*/
		//����NewBase��0x600000,���ļ������õ�ȱʡImageBase��0x400000,������ƫ��������0x200000
		//ע���ض�λ���λ�ÿ��ܺ�Ӳ���ļ��е�ƫ�Ƶ�ַ��ͬ��Ӧ��ʹ�ü��غ�ĵ�ַ

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
#ifdef _WIN64
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG64)pDosHeader + pDosHeader->e_lfanew);
		PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((ULONGLONG)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
#else
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((unsigned long)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
#endif 



		// �ж��Ƿ��� �ض�λ��
		if ((PVOID)pLoc == (PVOID)pDosHeader)
		{
			// �ض�λ�� Ϊ��
			return TRUE;
		}

		while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //��ʼɨ���ض�λ��
		{
			WORD *pLocData = (WORD *)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));
			//���㱾����Ҫ�������ض�λ���ַ������Ŀ
			int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			for (int i = 0; i < nNumberOfReloc; i++)
			{
				// ÿ��WORD����������ɡ���4λָ�����ض�λ�����ͣ�WINNT.H�е�һϵ��IMAGE_REL_BASED_xxx�������ض�λ���͵�ȡֵ��
				// ��12λ�������VirtualAddress���ƫ�ƣ�ָ���˱�������ض�λ��λ�á�

#ifdef _WIN64
				if ((DWORD)(pLocData[i] & 0x0000F000) == 0x0000A000)
				{
					// 64λdll�ض�λ��IMAGE_REL_BASED_DIR64
					// ����IA-64�Ŀ�ִ���ļ����ض�λ�ƺ�����IMAGE_REL_BASED_DIR64���͵ġ�

					ULONGLONG* pAddress = (ULONGLONG *)((PBYTE)pDosHeader + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
					ULONGLONG ullDelta = (ULONGLONG)pDosHeader - pNtHeaders->OptionalHeader.ImageBase;
					*pAddress += ullDelta;

				}
#else

				if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //����һ����Ҫ�����ĵ�ַ
				{
					// 32λdll�ض�λ��IMAGE_REL_BASED_HIGHLOW
					// ����x86�Ŀ�ִ���ļ������еĻ�ַ�ض�λ����IMAGE_REL_BASED_HIGHLOW���͵ġ�

					DWORD* pAddress = (DWORD *)((PBYTE)pDosHeader + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
					DWORD dwDelta = (DWORD)pDosHeader - pNtHeaders->OptionalHeader.ImageBase;
					*pAddress += dwDelta;

				}
#endif
			}

			//ת�Ƶ���һ���ڽ��д���
			pLoc = (PIMAGE_BASE_RELOCATION)((PBYTE)pLoc + pLoc->SizeOfBlock);
		}

		return TRUE;
	}


	// ��дPE�ļ��������Ϣ
	// lpBaseAddress: �ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ
	// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE
	GRAVITY_ENGINE_API BOOL DoImportTable(LPVOID lpBaseAddress)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pDosHeader +
			pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		// ѭ������DLL������е�DLL����ȡ������еĺ�����ַ
		char *lpDllName = NULL;
		HMODULE hDll = NULL;
		PIMAGE_THUNK_DATA lpImportNameArray = NULL;
		PIMAGE_IMPORT_BY_NAME lpImportByName = NULL;
		PIMAGE_THUNK_DATA lpImportFuncAddrArray = NULL;
		FARPROC lpFuncAddress = NULL;
		DWORD i = 0;

		while (TRUE)
		{
			if (0 == pImportTable->OriginalFirstThunk)
			{
				break;
			}

			// ��ȡ�������DLL�����Ʋ�����DLL
			lpDllName = (char *)((DWORD)pDosHeader + pImportTable->Name);
			hDll = ::GetModuleHandleA(lpDllName);
			if (NULL == hDll)
			{
				hDll = ::LoadLibraryA(lpDllName);
				if (NULL == hDll)
				{
					pImportTable++;
					continue;
				}
			}

			i = 0;
			// ��ȡOriginalFirstThunk�Լ���Ӧ�ĵ��뺯�����Ʊ��׵�ַ
			lpImportNameArray = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + pImportTable->OriginalFirstThunk);
			// ��ȡFirstThunk�Լ���Ӧ�ĵ��뺯����ַ���׵�ַ
			lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + pImportTable->FirstThunk);
			while (TRUE)
			{
				if (0 == lpImportNameArray[i].u1.AddressOfData)
				{
					break;
				}

				// ��ȡIMAGE_IMPORT_BY_NAME�ṹ
				lpImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDosHeader + lpImportNameArray[i].u1.AddressOfData);

				// �жϵ�����������ŵ������Ǻ������Ƶ���
				if (0x80000000 & lpImportNameArray[i].u1.Ordinal)
				{
					// ��ŵ���
					// ��IMAGE_THUNK_DATAֵ�����λΪ1ʱ����ʾ��������ŷ�ʽ���룬��ʱ����λ��������һ���������
					lpFuncAddress = GetProcAddress(hDll, (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));
				}
				else
				{
					// ���Ƶ���
					lpFuncAddress = GetProcAddress(hDll, (LPCSTR)lpImportByName->Name);
				}
				// ע��˴��ĺ�����ַ��ĸ�ֵ��Ҫ����PE��ʽ����װ�أ���Ҫ�����ˣ�����
				lpImportFuncAddrArray[i].u1.Function = (DWORD)lpFuncAddress;
				i++;
			}

			pImportTable++;
		}

		return TRUE;
	}


	// �޸�PE�ļ����ػ�ַIMAGE_NT_HEADERS.OptionalHeader.ImageBase
	// lpBaseAddress: �ڴ�EXE���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ
	// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE
	GRAVITY_ENGINE_API BOOL SetImageBase(LPVOID lpBaseAddress)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		pNtHeaders->OptionalHeader.ImageBase = (ULONG32)lpBaseAddress;

		return TRUE;
	}


	// ����DLL����ں���DllMain,������ַ��ΪPE�ļ�����ڵ�IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
	// lpBaseAddress: �ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ
	// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE
	GRAVITY_ENGINE_API BOOL CallDllMain(LPVOID lpBaseAddress)
	{
		typedef_DllMain DllMain = NULL;
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		DllMain = (typedef_DllMain)((ULONG32)pDosHeader + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
		// ������ں���,���ӽ���DLL_PROCESS_ATTACH
		BOOL bRet = DllMain((HINSTANCE)lpBaseAddress, DLL_PROCESS_ATTACH, NULL);
		if (FALSE == bRet)
		{
			ShowError("DllMain");
		}

		return bRet;
	}

	// ��ת��PE����ڵ㴦ִ��, ������ַ��ΪPE�ļ�����ڵ�IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
	// lpBaseAddress: �ڴ�PE���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ
	// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE

	GRAVITY_ENGINE_API BOOL CallExeEntry(LPVOID lpBaseAddress)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		LPVOID lpExeEntry = (LPVOID)((ULONG32)pDosHeader + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
		// ��ת����ڵ㴦ִ��

		/*
		typedef void(*EntryProitCall)();
		EntryProitCall call = (EntryProitCall)lpExeEntry;
		call();*/

		/*__asm
		{
			mov eax, lpExeEntry
			jmp eax
		}*/

		CloseHandle(CreateThread(0, NULL, (LPTHREAD_START_ROUTINE)lpExeEntry, NULL, NULL, 0));
		return TRUE;
	}


	// ģ��GetProcAddress��ȡ�ڴ�DLL�ĵ�������
	// lpBaseAddress: �ڴ�DLL�ļ����ص������еļ��ػ�ַ
	// lpszFuncName: ��������������
	// ����ֵ: ���ص��������ĵĵ�ַ
	GRAVITY_ENGINE_API LPVOID MmGetProcAddress(LPVOID lpBaseAddress, PCCH lpszFuncName)
	{
		LPVOID lpFunc = NULL;
		// ��ȡ������
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		// ��ȡ�����������
		PDWORD lpAddressOfNamesArray = (PDWORD)((DWORD)pDosHeader + pExportTable->AddressOfNames);
		PCHAR lpFuncName = NULL;
		PWORD lpAddressOfNameOrdinalsArray = (PWORD)((DWORD)pDosHeader + pExportTable->AddressOfNameOrdinals);
		WORD wHint = 0;
		PDWORD lpAddressOfFunctionsArray = (PDWORD)((DWORD)pDosHeader + pExportTable->AddressOfFunctions);

		DWORD dwNumberOfNames = pExportTable->NumberOfNames;
		DWORD i = 0;
		// ����������ĵ�������������, ������ƥ��
		for (i = 0; i < dwNumberOfNames; i++)
		{
			lpFuncName = (PCHAR)((DWORD)pDosHeader + lpAddressOfNamesArray[i]);
			if (0 == ::lstrcmpiA(lpFuncName, lpszFuncName))
			{
				// ��ȡ����������ַ
				wHint = lpAddressOfNameOrdinalsArray[i];
				lpFunc = (LPVOID)((DWORD)pDosHeader + lpAddressOfFunctionsArray[wHint]);
				break;
			}
		}

		return lpFunc;
	}


	// �ͷŴ��ڴ���ص�DLL�������ڴ�Ŀռ�
	// lpBaseAddress: �ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ��е��ڴ��ַ
	// ����ֵ: �ɹ�����TRUE�����򷵻�FALSE
	GRAVITY_ENGINE_API BOOL MmFreeLibrary(LPVOID lpBaseAddress)
	{
		BOOL bRet = FALSE;

		if (NULL == lpBaseAddress)
		{
			return bRet;
		}

		bRet = ::VirtualFree(lpBaseAddress, 0, MEM_RELEASE);
		lpBaseAddress = NULL;

		return bRet;
	}

}