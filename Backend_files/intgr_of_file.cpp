#include"stllist.h"

void CreateFilesLowHighIntg(WCHAR* integritySid, WCHAR* path)
{
	BOOL fRet;
	HANDLE hToken = NULL;
	HANDLE hNewToken = NULL;
	PSID pIntegritySid = NULL;
	TOKEN_MANDATORY_LABEL TIL = { 0 };
	PROCESS_INFORMATION ProcInfo = { 0 };
	STARTUPINFO StartupInfo = { 0 };
    WCHAR wszProcessName[MAX_PATH];
    WCHAR wszIntegritySid[20];

    std::wcscpy(wszIntegritySid ,integritySid);
    std::wcscpy(wszProcessName ,path);

	//WCHAR wszIntegritySid[20] = L"S-1-16-4096"; //low
	//WCHAR wszIntegritySid[20] = L"S-1-16-8192";//medium 
    //WCHAR wszIntegritySid[20] = L"S-1-16-12288"; //high
	//WCHAR wszIntegritySid[20] = L"S-1-16-0"; untrusted 

    fRet = OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken);
	if (!fRet)
	{
		printf("[-] OpenProcessToken - failed %u\n", GetLastError());
	}

	fRet = DuplicateTokenEx(hToken, 0, NULL, SecurityImpersonation, TokenPrimary, &hNewToken);
	if (!fRet)
	{
		printf("[-] DuplicateTokenEx - failed %u\n", GetLastError());
	}

	fRet = ConvertStringSidToSidW(wszIntegritySid, &pIntegritySid);
	if (!fRet)
	{
		printf("[-] ConvertStringSidToSid - failed %u\n", GetLastError());
	}
	TIL.Label.Attributes = SE_GROUP_INTEGRITY;
	TIL.Label.Sid = pIntegritySid;

    fRet = SetTokenInformation(hNewToken, TokenIntegrityLevel, &TIL, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid));
	if (!fRet)
	{
		printf("[-] SetTokenInformation - failed %u\n", GetLastError());
	}

    fRet = CreateProcessAsUserW(hNewToken, NULL, wszProcessName,NULL, NULL, FALSE, 0,NULL, NULL, (LPSTARTUPINFOW)&StartupInfo, &ProcInfo);
}













