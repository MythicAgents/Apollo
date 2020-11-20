#include <iostream>
#include "clr.hpp"
#include "asm.hpp"
#include <stdio.h>
#include <fstream>

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif // !_CRT_SECURE_NO_WARNINGS


void callback0(const wchar_t* p)
{
    std::wcout << L"Callback 0: Message: " << p << std::endl;
}

void callback1(const wchar_t* p)
{
    std::wcout << L"Callback 1: " << p << std::endl;
    auto tmp = *((char*)0);
}


class CppClassEx {
public:
    int fn() {
        return 10;
    }

    int excepted(const wchar_t* p) {
        std::wcout << L"Hello from unmanaged C++ land! " << p << std::endl;
        throw std::runtime_error("Failsauce!");
        return 20;
    }
};

std::vector<uint8_t> read_vector_from_disk(std::string file_path)
{
    std::ifstream instream(file_path, std::ios::in | std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(instream)), std::istreambuf_iterator<char>());
    return data;
}

extern "C" __declspec(dllexport) void __cdecl InitializeNamedPipeServer(LPVOID lpUserdata, DWORD nUserdataLen)
{
    if (nUserdataLen) {
#ifdef _DEBUG
        FILE* fp = fopen("C:\\Users\\Reznok\\Desktop\\debug.txt", "w");
#endif // DEBUG
        DWORD length = nUserdataLen + 1; // 36 + nullbyte
#ifdef _DEBUG
        fprintf(fp, "Length: %d\n", length);
#endif // DEBUG
        LPSTR buffer = (LPSTR)malloc(length);
        LPWSTR pipeName;
        ZeroMemory(buffer, length);
        sprintf_s(buffer, length, "%s", (LPSTR)lpUserdata);
#ifdef _DEBUG
        fprintf(fp, "Buffer: %s\n", buffer);
#endif // DEBUG
        DWORD sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, buffer, nUserdataLen, NULL, 0);
#ifdef _DEBUG
        fprintf(fp, "Size Needed: %d\n", sizeNeeded);
#endif // DEBUG
        pipeName = (LPWSTR)malloc(sizeNeeded*2+1);
        ZeroMemory(pipeName, sizeNeeded*2+1);
        MultiByteToWideChar(CP_UTF8, 0, buffer, length, pipeName, sizeNeeded*2+1);
#ifdef _DEBUG
        fwprintf(fp, L"Wide string version: %s\n", pipeName);
#endif // DEBUG
        DWORD bytes = 0;
        std::vector<uint8_t> vec(std::begin(rawData), std::end(rawData));
        clr::ClrDomain dom;
        auto res = dom.load(vec);


        if (!res) {
            std::cout << "Failed to load module!" << std::endl;
            return;
        }

        else {
#ifdef _DEBUG
            fwprintf(fp, L"Assembly Loaded");
#endif // DEBUG
        }

#ifdef _DEBUG
        fprintf(fp, "Invoking...\n");
#endif // DEBUG
        res->invoke_static(L"ScreenshotRunner.Program", L"InitializeNamedPipeServer", pipeName);
    }
}

int wmain(int argc, wchar_t** argv)
{
#if _DEBUG
    printf("Beginning execution...\n");
#endif
    LPSTR test = "HelloWorld";
    DWORD len = strlen(test);
    InitializeNamedPipeServer(test, len);
}