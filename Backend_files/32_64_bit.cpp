#include"stllist.h"
#include <tchar.h>

typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

LPFN_ISWOW64PROCESS fnIsWow64Process;

void x_32_64(list <info> &gqlist)
{
	BOOL bIsWow64 = FALSE;

	//IsWow64Process is not available on all supported versions of Windows.
	//Use GetModuleHandle to get a handle to the DLL that contains the function
	//and GetProcAddress to get a pointer to the function if available.

    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

	list <info> ::iterator it;
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		if (NULL != fnIsWow64Process)
		{
			if (!fnIsWow64Process(OpenProcess(PROCESS_QUERY_INFORMATION, false, it->num_PID), &bIsWow64))
			{
                it->x_bit = 9; // error occured
			}
		}
		if (bIsWow64)
		{
			it->x_bit = 64;
		}
		else
		{
			it->x_bit = 32;
		}
	}
	
}
