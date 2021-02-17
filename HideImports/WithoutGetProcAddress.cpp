
#include "hideimports.h"



HRESULT IhateUNICODE_STRING(LPCOLESTR pszW, LPSTR* ppszA)
{
    ULONG cbAnsi, cCharacters;
    DWORD dwError;
    if (pszW == NULL) {
        *ppszA = NULL;
        return NOERROR;
    }
    cCharacters = wcslen(pszW) + 1;
    cbAnsi = cCharacters * 2;
    *ppszA = (LPSTR)CoTaskMemAlloc(cbAnsi);
    if (NULL == *ppszA)
        return E_OUTOFMEMORY;
    if (0 == WideCharToMultiByte(CP_ACP, 0, pszW, cCharacters, *ppszA, cbAnsi, NULL, NULL)) {
        dwError = GetLastError();
        CoTaskMemFree(*ppszA);
        *ppszA = NULL;
        return HRESULT_FROM_WIN32(dwError);
    }
    return NOERROR;
}

unsigned __int64 FindDLLBase(const char* dll_name)
{
    unsigned __int64 ret = 0x0;
    // Get Thread Environment Block
    // https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
    // https://blog.christophetd.fr/hiding-windows-api-imports-with-a-customer-loader/
    PTEB teb = reinterpret_cast<PTEB>(__readgsqword(offsetof(NT_TIB, Self)));
    //typedef struct _LDR_DATA_TABLE_ENTRY {
    //    LIST_ENTRY InMemoryOrderLinks;
    //    PVOID DllBase;
    //    UNICODE_STRING FullDllName;
    //} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
    PPEB_LDR_DATA loader = teb->ProcessEnvironmentBlock->Ldr;
    PLIST_ENTRY head = &loader->InMemoryOrderModuleList;
    PLIST_ENTRY ci = head->Flink;
    // loop LIST_ENTRY
    while (ci != head) {
        PLDR_DATA_TABLE_ENTRY ciDLL = CONTAINING_RECORD(
            ci, 
            LDR_DATA_TABLE_ENTRY, 
            InMemoryOrderLinks);
        char* NDLLName;
        PVOID dlladr = ciDLL->DllBase;
        IhateUNICODE_STRING(ciDLL->FullDllName.Buffer, &NDLLName);
        // KERNEL32.DLL @ C:\Windows\System32\KERNEL32.DLL
        char* FOUND = strstr(NDLLName, dll_name);
        if (FOUND != NULL) {
            ret = (unsigned __int64)dlladr;
            printf("[+] Found %s @ %p \n", dll_name, ret);
            return ret;
        }
        ci = ci->Flink;
    }

    return ret;
}

unsigned __int64 FindFunction(unsigned __int64 dllbaseAdrr, const char* FunctionName)
{
    unsigned __int64 ret = 0x0;
    // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
    PIMAGE_DOS_HEADER bPEH = (PIMAGE_DOS_HEADER)dllbaseAdrr;
    PIMAGE_NT_HEADERS NThead = (PIMAGE_NT_HEADERS)(dllbaseAdrr + bPEH->e_lfanew);
    DWORD DATA_DIRECTORYVA = NThead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY EXTable = (PIMAGE_EXPORT_DIRECTORY)(dllbaseAdrr + DATA_DIRECTORYVA);
    DWORD*  rvas    = (DWORD*)(dllbaseAdrr + EXTable->AddressOfFunctions);
    WORD*  OrdTable = (WORD*)(dllbaseAdrr + EXTable->AddressOfNameOrdinals);
    DWORD* Fnames   = (DWORD*)(dllbaseAdrr + EXTable->AddressOfNames);
    DWORD  nl = EXTable->NumberOfNames;
    for (int i = 0; i < nl; ++i) {
        char* funcName = (char*)(dllbaseAdrr + OrdTable[i]);
        bool nfound = _strcmpi(funcName, FunctionName);
        if (!nfound) {
            unsigned __int64 rva = rvas[OrdTable[i]];
            unsigned __int64 funcAddr = dllbaseAdrr + rva;
            printf("[+] Found %s @ %p RVA@%p %s \n", FunctionName, funcAddr, rva);
            return funcAddr;
        }
    }
    return ret;
}


