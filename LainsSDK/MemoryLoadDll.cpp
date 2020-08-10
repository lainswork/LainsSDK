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
			//LOGFMTI("申请内存失败");
			printf(xorstr("申请内存失败\n").crypt_get());
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
			printf(xorstr("参数校验失败\n").crypt_get());
			return false;
		}

		//旧的权限
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

		//获取目标的导入函数,用自己的ntdll进行定位


		param.LdrGetProcedureAddress = (LdrGetProcedureAddressT)GetProcAddress(NTDLL, xorstr("LdrGetProcedureAddress").crypt_get());;
		param.dwNtAllocateVirtualMemory = (NtAllocateVirtualMemoryT)GetProcAddress(NTDLL, xorstr("NtAllocateVirtualMemory").crypt_get());
		param.pLdrLoadDll = (LdrLoadDllT)GetProcAddress(NTDLL, xorstr("LdrLoadDll").crypt_get());
		param.RtlInitAnsiString = (RtlInitAnsiStringT)GetProcAddress(NTDLL, xorstr("RtlInitAnsiString").crypt_get());
		param.RtlAnsiStringToUnicodeString = (RtlAnsiStringToUnicodeStringT)GetProcAddress(NTDLL, xorstr("RtlAnsiStringToUnicodeString").crypt_get());
		param.RtlFreeUnicodeString = (RtlFreeUnicodeStringT)GetProcAddress(NTDLL, xorstr("RtlFreeUnicodeString").crypt_get());


		//申请内存,把shellcode和DLL数据,和参数复制到目标进程
		//PBYTE  pAddress = (PBYTE)VirtualAllocEx(hProcess, 0, *dllSize + shellCodeSize + sizeof(PARAMX) + 0x100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//安全起见,大小多加0x100
		//IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress, IN ULONG ZeroBits, IN OUT PULONG RegionSize, IN ULONG AllocationType, IN ULONG Protect
		PBYTE  pAddress = (PBYTE)VirtualAllocEx(
			hProcess,
			0,
			*dllSize + shellCodeSize + sizeof(PARAMX) + 0x100,
			//&dWrited,
			MEM_COMMIT,
			PAGE_EXECUTE_READWRITE);

		if (pAddress == NULL) {
			//LOGFMTI("申请内存失败");
			printf(xorstr("申请内存失败\n").crypt_get());
			
			return false;
		}
		//修成下DLL数据的地址
		param.lpFileData = pAddress;
		//DLL数据写入到目标
		//if (!WriteProcessMemory(hProcess, pAddress, *dllBuffer, *dllSize, &dWrited)) {
		if (!WriteProcessMemory(hProcess, pAddress, *dllBuffer, *dllSize, &dWrited)) {
			//LOGFMTI("DLL数据写入到目标失败");
			printf(xorstr("DLL数据写入到目标失败\n").crypt_get());
			return false;
		}
		//shellcode写入到目标
		//if (!WriteProcessMemory(hProcess, pAddress + *dllSize, shellCodeBuffer, shellCodeSize, &dWrited)) {
		if (!WriteProcessMemory(hProcess, pAddress + *dllSize, shellCodeBuffer, shellCodeSize, &dWrited)) {
			//LOGFMTI("shellcode写入到目标失败");
			printf(xorstr("shellcode写入到目标失败\n").crypt_get());
			return false;
		}
		//参数写入到目标
		//if (!WriteProcessMemory(hProcess, pAddress + *dllSize + shellCodeSize, &param, sizeof(PARAMX), &dWrited)) {
		if (!WriteProcessMemory(hProcess, pAddress + *dllSize + shellCodeSize, &param, sizeof(PARAMX), &dWrited)) {
			//LOGFMTI("参数写入到目标失败");
			printf(xorstr("参数写入到目标失败\n").crypt_get());
			return false;
		}

		//启动注入线程=pAddress+ dllsize,参数=pAddress + dllsize+ shellcodesize;
		HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)(pAddress + *dllSize), pAddress + *dllSize + shellCodeSize, 0, 0);
		if (hThread)
		{
			DWORD dExecCode = 0;
			//LOGFMTI("等待注入线程执行完毕....\n");
			printf(xorstr("等待注入线程执行完毕....\n").crypt_get());
			WaitForSingleObject(hThread, -1);
			GetExitCodeThread(hThread, &dExecCode);
#ifdef _WIN64

			printf(xorstr("注入完成.... 0x%llX\n").crypt_get(), dExecCode + (((DWORD64)pAddress >> 32) << 32));//如果是64位,基于内存申请的地址逐步累加,可以大概算出注入的模块基址
			*imageBase = (PVOID)(dExecCode + (((DWORD64)pAddress >> 32) << 32));
#else
			//LOGFMTI("注入完成.... 0x%X\n", dExecCode);//如果是32位注入,这里的dExecCode=注入的模块基址
			*imageBase = (PVOID)dExecCode;
#endif

		//释放掉申请的内存
			VirtualFreeEx(hProcess, pAddress, 0, MEM_FREE);
			CloseHandle(hThread);
			CloseHandle(hProcess);

		}
		else 
		{
			printf(xorstr("注入失败!!").crypt_get());
			return false;
		}

		return true;
	}


	/// <summary>
	/// 通过序号或者函数名找到导出函数地址
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
			printf(xorstr("%s函数在系统模块%s中,尝试找到他,找到的地址: %p").crypt_get(), lpProcName, szDllName, hForward);
			pAddress = GetExportAddress(hForward, szFunctionName);
		}

		return (FARPROC)pAddress;
	}


	//GRAVITY_ENGINE_API bool MemoryLoadDllExAPC(IN HANDLE hProcess, IN DWORD dwTid,IN PVOID* dllBuffer, IN ULONG* dllSize, OUT ULONG_PTR* imageBase) {
	//	if (*dllBuffer == NULL || *dllSize < 10 || hProcess == 0) {
	//		LOGFMTI("参数校验失败");
	//		return false;
	//	}
	//
	//	//旧的权限
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
	//	//获取目标的导入函数,用自己的ntdll进行定位
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
	//	//申请内存,把shellcode和DLL数据,和参数复制到目标进程
	//	//PBYTE  pAddress = (PBYTE)VirtualAllocEx(hProcess, 0, *dllSize + shellCodeSize + sizeof(PARAMX) + 0x100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//安全起见,大小多加0x100
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
	//		LOGFMTI("申请内存失败");
	//		return false;
	//	}
	//	//修成下DLL数据的地址
	//	param.lpFileData = pAddress;
	//	//DLL数据写入到目标
	//	//if (!WriteProcessMemory(hProcess, pAddress, *dllBuffer, *dllSize, &dWrited)) {
	//	if (!NtWriteVirtualMemory(hProcess, pAddress, *dllBuffer, *dllSize, &dWrited)) {
	//		LOGFMTI("DLL数据写入到目标失败");
	//		return false;
	//	}
	//	//shellcode写入到目标
	//	//if (!WriteProcessMemory(hProcess, pAddress + *dllSize, shellCodeBuffer, shellCodeSize, &dWrited)) {
	//	if (!NtWriteVirtualMemory(hProcess, pAddress + *dllSize, shellCodeBuffer, shellCodeSize, &dWrited)) {
	//		LOGFMTI("shellcode写入到目标失败");
	//		return false;
	//	}
	//	//参数写入到目标
	//	//if (!WriteProcessMemory(hProcess, pAddress + *dllSize + shellCodeSize, &param, sizeof(PARAMX), &dWrited)) {
	//	if (!NtWriteVirtualMemory(hProcess, pAddress + *dllSize + shellCodeSize, &param, sizeof(PARAMX), &dWrited)) {
	//		LOGFMTI("参数写入到目标失败");
	//		return false;
	//	}
	//
	////	//启动注入线程=pAddress+ dllsize,参数=pAddress + dllsize+ shellcodesize;
	////	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)(pAddress + *dllSize), pAddress + *dllSize + shellCodeSize, 0, 0);
	////	if (hThread)
	////	{
	////		DWORD dExecCode = 0;
	////		LOGFMTI("等待注入线程执行完毕....\n");
	////		WaitForSingleObject(hThread, -1);
	////		GetExitCodeThread(hThread, &dExecCode);
	////#ifdef _WIN64
	////
	////		LOGFMTI("注入完成.... 0x%llX\n", dExecCode + (((DWORD64)pAddress >> 32) << 32));//如果是64位,基于内存申请的地址逐步累加,可以大概算出注入的模块基址
	////#else
	////		LOGFMTI("注入完成.... 0x%llX\n", dExecCode);//如果是32位注入,这里的dExecCode=注入的模块基址
	////#endif
	////
	////		//释放掉申请的内存
	////		VirtualFreeEx(hProcess, pAddress, 0, MEM_FREE);
	////		CloseHandle(hThread);
	////		CloseHandle(hProcess);
	////
	////	}
	////	else {
	////		LOGFMTI("注入失败!!");
	////		return false;
	////	}
	//
	//	
	//	//6.根据线程Tid,打开线程句柄
	//	HANDLE hThread = NULL;
	//	NtOpenThread(&hThread,THREAD_ALL_ACCESS, FALSE, dwTid);
	//	if (NULL == hThread)
	//	{
	//		return;
	//	}
	//	//7.给APC队列中插入回调函数
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



	// 模拟LoadLibrary加载内存DLL文件到进程中
	// lpData: 内存DLL文件数据的基址
	// dwSize: 内存DLL文件的内存大小
	// 返回值: 内存DLL加载到进程的加载基址
	GRAVITY_ENGINE_API LPVOID MmLoadLibrary(LPVOID lpData, DWORD dwSize)
	{
		LPVOID lpBaseAddress = NULL;

		// 获取镜像大小
		DWORD dwSizeOfImage = GetSizeOfImage(lpData);

		// 在进程中开辟一个可读、可写、可执行的内存块
		lpBaseAddress = ::VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NULL == lpBaseAddress)
		{
			ShowError(xorstr("VirtualAlloc").crypt_get());
			return NULL;
		}
		::RtlZeroMemory(lpBaseAddress, dwSizeOfImage);

		// 将内存DLL数据按SectionAlignment大小对齐映射到进程内存中
		if (FALSE == MmMapFile(lpData, lpBaseAddress))
		{
			ShowError(xorstr("MmMapFile").crypt_get());
			return NULL;
		}

		// 修改PE文件重定位表信息
		if (FALSE == DoRelocationTable(lpBaseAddress))
		{
			ShowError(xorstr("DoRelocationTable").crypt_get());
			return NULL;
		}

		// 填写PE文件导入表信息
		if (FALSE == DoImportTable(lpBaseAddress))
		{
			ShowError(xorstr("DoImportTable").crypt_get());
			return NULL;
		}

		//修改页属性。应该根据每个页的属性单独设置其对应内存页的属性。
		//统一设置成一个属性PAGE_EXECUTE_READWRITE
		DWORD dwOldProtect = 0;
		if (FALSE == ::VirtualProtect(lpBaseAddress, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			ShowError(xorstr("VirtualProtect").crypt_get());
			return NULL;
		}

		// 修改PE文件加载基址IMAGE_NT_HEADERS.OptionalHeader.ImageBase
		if (FALSE == SetImageBase(lpBaseAddress))
		{
			ShowError(xorstr("SetImageBase").crypt_get());
			return NULL;
		}

		// 调用DLL的入口函数DllMain,函数地址即为PE文件的入口点IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
		if (FALSE == CallDllMain(lpBaseAddress))
		{
			ShowError(xorstr("CallDllMain").crypt_get());
			return NULL;
		}

		return lpBaseAddress;
	}



	//不执行dllmain
	GRAVITY_ENGINE_API LPVOID MmLoadLibraryNoCallDllMain(LPVOID lpData, DWORD dwSize)
	{
		LPVOID lpBaseAddress = NULL;

		// 获取镜像大小
		DWORD dwSizeOfImage = GetSizeOfImage(lpData);

		// 在进程中开辟一个可读、可写、可执行的内存块
		lpBaseAddress = ::VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NULL == lpBaseAddress)
		{
			ShowError("VirtualAlloc");
			return NULL;
		}
		::RtlZeroMemory(lpBaseAddress, dwSizeOfImage);

		// 将内存DLL数据按SectionAlignment大小对齐映射到进程内存中
		if (FALSE == MmMapFile(lpData, lpBaseAddress))
		{
			ShowError("MmMapFile");
			return NULL;
		}

		// 修改PE文件重定位表信息
		if (FALSE == DoRelocationTable(lpBaseAddress))
		{
			ShowError("DoRelocationTable");
			return NULL;
		}

		// 填写PE文件导入表信息
		if (FALSE == DoImportTable(lpBaseAddress))
		{
			ShowError("DoImportTable");
			return NULL;
		}

		//修改页属性。应该根据每个页的属性单独设置其对应内存页的属性。
		//统一设置成一个属性PAGE_EXECUTE_READWRITE
		DWORD dwOldProtect = 0;
		if (FALSE == ::VirtualProtect(lpBaseAddress, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			ShowError("VirtualProtect");
			return NULL;
		}

		// 修改PE文件加载基址IMAGE_NT_HEADERS.OptionalHeader.ImageBase
		if (FALSE == SetImageBase(lpBaseAddress))
		{
			ShowError("SetImageBase");
			return NULL;
		}
		return lpBaseAddress;
	}


	// 判断是否有重定位表存在
	GRAVITY_ENGINE_API BOOL IsExistRelocationTable(LPVOID lpBaseAddress)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((unsigned long)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		// 判断是否有 重定位表
		if ((PVOID)pLoc == (PVOID)pDosHeader)
		{
			// 重定位表 为空
			return FALSE;
		}

		return TRUE;
	}


	// 模拟PE加载器加载内存EXE文件到进程中
	// lpData: 内存EXE文件数据的基址
	// dwSize: 内存EXE文件的内存大小
	// 返回值: 内存EXE加载到进程的加载基址
	GRAVITY_ENGINE_API LPVOID MmLoadExe(LPVOID lpData, DWORD dwSize)
	{
		LPVOID lpBaseAddress = NULL;

		// 获取镜像大小
		DWORD dwSizeOfImage = GetSizeOfImage(lpData);

		// 在进程中开辟一个可读、可写、可执行的内存块
		lpBaseAddress = ::VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NULL == lpBaseAddress)
		{
			ShowError("VirtualAlloc");
			return NULL;
		}
		::RtlZeroMemory(lpBaseAddress, dwSizeOfImage);

		// 将内存PE数据按SectionAlignment大小对齐映射到进程内存中
		if (FALSE == MmMapFile(lpData, lpBaseAddress))
		{
			ShowError("MmMapFile");
			return NULL;
		}

		// 修改PE文件重定位表信息
		if (FALSE == DoRelocationTable(lpBaseAddress))
		{
			ShowError("DoRelocationTable");
			return NULL;
		}

		// 填写PE文件导入表信息
		if (FALSE == DoImportTable(lpBaseAddress))
		{
			ShowError("DoImportTable");
			return NULL;
		}

		//修改页属性。应该根据每个页的属性单独设置其对应内存页的属性。
		//统一设置成一个属性PAGE_EXECUTE_READWRITE
		DWORD dwOldProtect = 0;
		if (FALSE == ::VirtualProtect(lpBaseAddress, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			ShowError("VirtualProtect");
			return NULL;
		}

		// 修改PE文件加载基址IMAGE_NT_HEADERS.OptionalHeader.ImageBase
		if (FALSE == SetImageBase(lpBaseAddress))
		{
			ShowError("SetImageBase");
			return NULL;
		}

		// 跳转到PE的入口点处执行, 函数地址即为PE文件的入口点IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
		if (FALSE == CallExeEntry(lpBaseAddress))
		{
			ShowError("CallExeEntry");
			return NULL;
		}

		return lpBaseAddress;
	}



	// 模拟PE加载器加载内存EXE文件到进程中
	// lpData: 内存EXE文件数据的基址
	// dwSize: 内存EXE文件的内存大小
	// 返回值: 内存EXE加载到进程的加载基址
	GRAVITY_ENGINE_API LPVOID MmLoadExeNoCallMain(LPVOID lpData, DWORD dwSize)
	{
		LPVOID lpBaseAddress = NULL;

		// 获取镜像大小
		DWORD dwSizeOfImage = GetSizeOfImage(lpData);

		// 在进程中开辟一个可读、可写、可执行的内存块
		lpBaseAddress = ::VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NULL == lpBaseAddress)
		{
			ShowError("VirtualAlloc");
			return NULL;
		}
		::RtlZeroMemory(lpBaseAddress, dwSizeOfImage);

		// 将内存PE数据按SectionAlignment大小对齐映射到进程内存中
		if (FALSE == MmMapFile(lpData, lpBaseAddress))
		{
			ShowError("MmMapFile");
			return NULL;
		}

		// 修改PE文件重定位表信息
		if (FALSE == DoRelocationTable(lpBaseAddress))
		{
			ShowError("DoRelocationTable");
			return NULL;
		}

		// 填写PE文件导入表信息
		if (FALSE == DoImportTable(lpBaseAddress))
		{
			ShowError("DoImportTable");
			return NULL;
		}

		//修改页属性。应该根据每个页的属性单独设置其对应内存页的属性。
		//统一设置成一个属性PAGE_EXECUTE_READWRITE
		DWORD dwOldProtect = 0;
		if (FALSE == ::VirtualProtect(lpBaseAddress, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			ShowError("VirtualProtect");
			return NULL;
		}

		// 修改PE文件加载基址IMAGE_NT_HEADERS.OptionalHeader.ImageBase
		if (FALSE == SetImageBase(lpBaseAddress))
		{
			ShowError("SetImageBase");
			return NULL;
		}

		return lpBaseAddress;
	}


	// 根据PE结构,获取PE文件加载到内存后的镜像大小
	// lpData: 内存DLL文件数据的基址
	// 返回值: 返回PE文件结构中IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage值的大小
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


	// 将内存DLL数据按SectionAlignment大小对齐映射到进程内存中
	// lpData: 内存DLL文件数据的基址
	// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址
	// 返回值: 成功返回TRUE，否则返回FALSE
	GRAVITY_ENGINE_API BOOL MmMapFile(LPVOID lpData, LPVOID lpBaseAddress)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpData;
#ifdef _WIN64
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG64)pDosHeader + pDosHeader->e_lfanew);
		// 获取SizeOfHeaders的值: 所有头+节表头的大小
		DWORD dwSizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
		// 获取节表的数量
		WORD wNumberOfSections = pNtHeaders->FileHeader.NumberOfSections;
		// 获取第一个节表头的地址
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONGLONG)pNtHeaders + sizeof(IMAGE_NT_HEADERS));

		// 加载 所有头+节表头的大小
		::RtlCopyMemory(lpBaseAddress, lpData, dwSizeOfHeaders);
		// 对齐SectionAlignment循环加载节表
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
		// 获取SizeOfHeaders的值: 所有头+节表头的大小
		DWORD dwSizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
		// 获取节表的数量
		WORD wNumberOfSections = pNtHeaders->FileHeader.NumberOfSections;
		// 获取第一个节表头的地址
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(IMAGE_NT_HEADERS));

		// 加载 所有头+节表头的大小
		::RtlCopyMemory(lpBaseAddress, lpData, dwSizeOfHeaders);
		// 对齐SectionAlignment循环加载节表
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


	// 对齐SectionAlignment
	// dwSize: 表示未对齐前内存的大小
	// dwAlignment: 对齐大小值
	// 返回值: 返回内存对齐之后的值
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


	// 修改PE文件重定位表信息
	// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址
	// 返回值: 成功返回TRUE，否则返回FALSE
	GRAVITY_ENGINE_API BOOL DoRelocationTable(LPVOID lpBaseAddress)
	{
		/* 重定位表的结构：
		// DWORD sectionAddress, DWORD size (包括本节需要重定位的数据)
		// 例如 1000节需要修正5个重定位数据的话，重定位表的数据是
		// 00 10 00 00   14 00 00 00      xxxx xxxx xxxx xxxx xxxx 0000
		// -----------   -----------      ----
		// 给出节的偏移  总尺寸=8+6*2     需要修正的地址           用于对齐4字节
		// 重定位表是若干个相连，如果address 和 size都是0 表示结束
		// 需要修正的地址是12位的，高4位是形态字，intel cpu下是3
		*/
		//假设NewBase是0x600000,而文件中设置的缺省ImageBase是0x400000,则修正偏移量就是0x200000
		//注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
#ifdef _WIN64
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG64)pDosHeader + pDosHeader->e_lfanew);
		PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((ULONGLONG)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
#else
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((unsigned long)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
#endif 



		// 判断是否有 重定位表
		if ((PVOID)pLoc == (PVOID)pDosHeader)
		{
			// 重定位表 为空
			return TRUE;
		}

		while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
		{
			WORD *pLocData = (WORD *)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));
			//计算本节需要修正的重定位项（地址）的数目
			int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			for (int i = 0; i < nNumberOfReloc; i++)
			{
				// 每个WORD由两部分组成。高4位指出了重定位的类型，WINNT.H中的一系列IMAGE_REL_BASED_xxx定义了重定位类型的取值。
				// 低12位是相对于VirtualAddress域的偏移，指出了必须进行重定位的位置。

#ifdef _WIN64
				if ((DWORD)(pLocData[i] & 0x0000F000) == 0x0000A000)
				{
					// 64位dll重定位，IMAGE_REL_BASED_DIR64
					// 对于IA-64的可执行文件，重定位似乎总是IMAGE_REL_BASED_DIR64类型的。

					ULONGLONG* pAddress = (ULONGLONG *)((PBYTE)pDosHeader + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
					ULONGLONG ullDelta = (ULONGLONG)pDosHeader - pNtHeaders->OptionalHeader.ImageBase;
					*pAddress += ullDelta;

				}
#else

				if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //这是一个需要修正的地址
				{
					// 32位dll重定位，IMAGE_REL_BASED_HIGHLOW
					// 对于x86的可执行文件，所有的基址重定位都是IMAGE_REL_BASED_HIGHLOW类型的。

					DWORD* pAddress = (DWORD *)((PBYTE)pDosHeader + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
					DWORD dwDelta = (DWORD)pDosHeader - pNtHeaders->OptionalHeader.ImageBase;
					*pAddress += dwDelta;

				}
#endif
			}

			//转移到下一个节进行处理
			pLoc = (PIMAGE_BASE_RELOCATION)((PBYTE)pLoc + pLoc->SizeOfBlock);
		}

		return TRUE;
	}


	// 填写PE文件导入表信息
	// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址
	// 返回值: 成功返回TRUE，否则返回FALSE
	GRAVITY_ENGINE_API BOOL DoImportTable(LPVOID lpBaseAddress)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pDosHeader +
			pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		// 循环遍历DLL导入表中的DLL及获取导入表中的函数地址
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

			// 获取导入表中DLL的名称并加载DLL
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
			// 获取OriginalFirstThunk以及对应的导入函数名称表首地址
			lpImportNameArray = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + pImportTable->OriginalFirstThunk);
			// 获取FirstThunk以及对应的导入函数地址表首地址
			lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + pImportTable->FirstThunk);
			while (TRUE)
			{
				if (0 == lpImportNameArray[i].u1.AddressOfData)
				{
					break;
				}

				// 获取IMAGE_IMPORT_BY_NAME结构
				lpImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDosHeader + lpImportNameArray[i].u1.AddressOfData);

				// 判断导出函数是序号导出还是函数名称导出
				if (0x80000000 & lpImportNameArray[i].u1.Ordinal)
				{
					// 序号导出
					// 当IMAGE_THUNK_DATA值的最高位为1时，表示函数以序号方式输入，这时，低位被看做是一个函数序号
					lpFuncAddress = GetProcAddress(hDll, (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));
				}
				else
				{
					// 名称导出
					lpFuncAddress = GetProcAddress(hDll, (LPCSTR)lpImportByName->Name);
				}
				// 注意此处的函数地址表的赋值，要对照PE格式进行装载，不要理解错了！！！
				lpImportFuncAddrArray[i].u1.Function = (DWORD)lpFuncAddress;
				i++;
			}

			pImportTable++;
		}

		return TRUE;
	}


	// 修改PE文件加载基址IMAGE_NT_HEADERS.OptionalHeader.ImageBase
	// lpBaseAddress: 内存EXE数据按SectionAlignment大小对齐映射到进程内存中的内存基址
	// 返回值: 成功返回TRUE，否则返回FALSE
	GRAVITY_ENGINE_API BOOL SetImageBase(LPVOID lpBaseAddress)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		pNtHeaders->OptionalHeader.ImageBase = (ULONG32)lpBaseAddress;

		return TRUE;
	}


	// 调用DLL的入口函数DllMain,函数地址即为PE文件的入口点IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
	// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址
	// 返回值: 成功返回TRUE，否则返回FALSE
	GRAVITY_ENGINE_API BOOL CallDllMain(LPVOID lpBaseAddress)
	{
		typedef_DllMain DllMain = NULL;
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		DllMain = (typedef_DllMain)((ULONG32)pDosHeader + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
		// 调用入口函数,附加进程DLL_PROCESS_ATTACH
		BOOL bRet = DllMain((HINSTANCE)lpBaseAddress, DLL_PROCESS_ATTACH, NULL);
		if (FALSE == bRet)
		{
			ShowError("DllMain");
		}

		return bRet;
	}

	// 跳转到PE的入口点处执行, 函数地址即为PE文件的入口点IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
	// lpBaseAddress: 内存PE数据按SectionAlignment大小对齐映射到进程内存中的内存基址
	// 返回值: 成功返回TRUE，否则返回FALSE

	GRAVITY_ENGINE_API BOOL CallExeEntry(LPVOID lpBaseAddress)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		LPVOID lpExeEntry = (LPVOID)((ULONG32)pDosHeader + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
		// 跳转到入口点处执行

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


	// 模拟GetProcAddress获取内存DLL的导出函数
	// lpBaseAddress: 内存DLL文件加载到进程中的加载基址
	// lpszFuncName: 导出函数的名字
	// 返回值: 返回导出函数的的地址
	GRAVITY_ENGINE_API LPVOID MmGetProcAddress(LPVOID lpBaseAddress, PCCH lpszFuncName)
	{
		LPVOID lpFunc = NULL;
		// 获取导出表
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		// 获取导出表的数据
		PDWORD lpAddressOfNamesArray = (PDWORD)((DWORD)pDosHeader + pExportTable->AddressOfNames);
		PCHAR lpFuncName = NULL;
		PWORD lpAddressOfNameOrdinalsArray = (PWORD)((DWORD)pDosHeader + pExportTable->AddressOfNameOrdinals);
		WORD wHint = 0;
		PDWORD lpAddressOfFunctionsArray = (PDWORD)((DWORD)pDosHeader + pExportTable->AddressOfFunctions);

		DWORD dwNumberOfNames = pExportTable->NumberOfNames;
		DWORD i = 0;
		// 遍历导出表的导出函数的名称, 并进行匹配
		for (i = 0; i < dwNumberOfNames; i++)
		{
			lpFuncName = (PCHAR)((DWORD)pDosHeader + lpAddressOfNamesArray[i]);
			if (0 == ::lstrcmpiA(lpFuncName, lpszFuncName))
			{
				// 获取导出函数地址
				wHint = lpAddressOfNameOrdinalsArray[i];
				lpFunc = (LPVOID)((DWORD)pDosHeader + lpAddressOfFunctionsArray[wHint]);
				break;
			}
		}

		return lpFunc;
	}


	// 释放从内存加载的DLL到进程内存的空间
	// lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址
	// 返回值: 成功返回TRUE，否则返回FALSE
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