// HideImports.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "hideimports.h"



int main()
{
    const char* funcname = "MessageBoxA";
    const char* dllname = "User32.dll";

    MsgBox MSGN, MSGI = NULL;

    // method 1
    GetModuleHandlePROC GetModuleHandle = NULL;
    GetProcAddressPROC GetProcAddress = NULL;
    unsigned __int64 kernel32_base = FindDLLBase("KERNEL32.DLL");
    GetProcAddress = (GetProcAddressPROC)FindFunction(kernel32_base, "GetProcAddress");
    GetModuleHandle = (GetModuleHandlePROC)FindFunction(kernel32_base, "GetModuleHandleA");
    MSGN = (MsgBox)GetProcAddress(GetModuleHandle(dllname), funcname);
    if (MSGN != NULL) {
        (*MSGN)(NULL, "You can't see MessageBoxA and GetProcAddress", "Hello Without GetProcAddress Import", MB_OK);
    }

    // method 2
    HMODULE hUser32 = LoadLibraryA(dllname);
    if (hUser32 != NULL) {
        MSGI = (MsgBox)GetProcAddress(hUser32, funcname);
    }
    if (MSGI != NULL) {
        (*MSGI)(NULL, "You can see GetProcAddress but you can't see MessageBoxA", "Hello Using GetProcAddress", MB_OK);
    }
    if (hUser32 != NULL) {
        FreeLibrary(hUser32);
    }
}

