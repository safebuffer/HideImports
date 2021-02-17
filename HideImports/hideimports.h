#pragma once
#include <iostream>
#include <windows.h> 
#include <Winternl.h> 
#include <stdio.h>



// Functions Prototype
typedef int(__stdcall* MsgBox)(HWND, LPCSTR, LPCSTR, UINT);
typedef HMODULE(__stdcall* GetModuleHandlePROC)(LPCSTR);
typedef HMODULE(__stdcall* GetProcAddressPROC)(HMODULE, LPCSTR);



unsigned __int64 FindDLLBase(const char* dll_name);
unsigned __int64 FindFunction(unsigned __int64 dll_base, const char* FunctionName);
