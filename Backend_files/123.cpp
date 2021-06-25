#define _WIN32_WINNT 0x0602
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)

#include"stllist.h"

void showlist(list <info> g)
{
	list <info> ::iterator it;
	for (it = g.begin(); it != g.end(); ++it)
	{
		cout <<"ProcessID "<<it->num_PID << " ImageFileName "<<it->name_PID<<'\n';
	}
}

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;// 2 byte char
} UNICODE_STRING;

typedef LONG KPRIORITY; // Thread priority

#include"stllist.h"

typedef struct _SYSTEM_PROCESS_INFORMATION_DETAILD
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads; //no need(at night 17.09)
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION_DETAILD, *PSYSTEM_PROCESS_INFORMATION_DETAILD;

typedef NTSTATUS(WINAPI *PFN_NT_QUERY_SYSTEM_INFORMATION)(
                                                            IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                                            IN OUT PVOID SystemInformation,
                                                            IN  ULONG SystemInformationLength,
                                                            OUT OPTIONAL  PULONG ReturnLength
                                                         );

void get_first_three(list <info> &gqlist)
{
	size_t bufferSize = 102400;
    PSYSTEM_PROCESS_INFORMATION_DETAILD procInfoDetailed = (PSYSTEM_PROCESS_INFORMATION_DETAILD)malloc(bufferSize);
	ULONG ReturnLength;
    PFN_NT_QUERY_SYSTEM_INFORMATION pfnNtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQuerySystemInformation");
	NTSTATUS status;

    while (TRUE)
    {
        status = pfnNtQuerySystemInformation(SystemProcessInformation, (PVOID)procInfoDetailed, bufferSize, &ReturnLength);
		if (status == STATUS_SUCCESS)
			break;

		bufferSize *= 2;
        procInfoDetailed = (PSYSTEM_PROCESS_INFORMATION_DETAILD)realloc((PVOID)procInfoDetailed, bufferSize);
	}

    for ( ; ; procInfoDetailed = (PSYSTEM_PROCESS_INFORMATION_DETAILD)(procInfoDetailed->NextEntryOffset + (PBYTE)procInfoDetailed)) {

		info name;
        name.num_PID = (uint64_t)(procInfoDetailed->UniqueProcessId);
		wchar_t buf[100];
		wmemset(buf, 0, 100);

        wmemcpy(buf, (procInfoDetailed->ImageName.Length && procInfoDetailed->ImageName.Buffer) ? procInfoDetailed->ImageName.Buffer : L"", 100);
		if (!wcscmp(buf, L"")) // don't copy proccesses without names!!
		{
			continue;
		}
          wcsncpy(name.name_PID, buf, 100);

		gqlist.push_back(name);
        if (procInfoDetailed->NextEntryOffset == 0) break;
	}

	exe_path(gqlist);
}

void exe_path(list <info> &gqlist)
{
	list <info> ::iterator it;

	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, it->num_PID);
		if (hProcess == NULL)
		{
			it->path = NULL;
			continue;
		}

		DWORD value = MAX_PATH;
		char buffer[MAX_PATH]="\0";

        // Retrieves the full name of the executable image for the specified process.
		QueryFullProcessImageName(hProcess, 0, buffer, &value);

		it->path = new char[strlen(buffer)+1];
		memset(it->path, 0, strlen(buffer) + 1);
		memcpy(it->path, buffer, strlen(buffer)*sizeof(char));
	}
}
