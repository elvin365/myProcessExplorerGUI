#include"stllist.h"
void mandatory_integrity(list <info>& gqlist)
{
	list <info> ::iterator it;

	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		HANDLE hToken;
		PTOKEN_MANDATORY_LABEL mandatoryLabel=NULL;
		MANDATORY_LEVEL integrityLevel;
		PCSTR integrityString;

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, it->num_PID);
        if (hProcess == NULL)
		{
			it->integrityString = "No info";
			continue;
		}

		OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
		DWORD returnLength = 0;

		GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &returnLength);// 902 // c NULL возвращает длину буффера

		mandatoryLabel =(PTOKEN_MANDATORY_LABEL)LocalAlloc(0, returnLength);

		GetTokenInformation(hToken, TokenIntegrityLevel, mandatoryLabel, returnLength, &returnLength);// теперь,когда длина буфера есть, пишем строку

        unsigned subAuthority = *GetSidSubAuthority(mandatoryLabel->Label.Sid, 0);

		switch (subAuthority)
		{
		case SECURITY_MANDATORY_UNTRUSTED_RID:
			integrityLevel = MandatoryLevelUntrusted;
			integrityString = "Untrusted";
			it->integrityString = "Untrusted";
			break;
		case SECURITY_MANDATORY_LOW_RID:
			integrityLevel = MandatoryLevelLow;
			integrityString = "Low";
			it->integrityString = "Low";
			break;
		case SECURITY_MANDATORY_MEDIUM_RID:
			integrityLevel = MandatoryLevelMedium;
			integrityString = "Medium";
			it->integrityString = "Medium";
			break;
		case SECURITY_MANDATORY_HIGH_RID:
			integrityLevel = MandatoryLevelHigh;
			integrityString = "High";
			it->integrityString = "High";
			break;
		case SECURITY_MANDATORY_SYSTEM_RID:
			integrityLevel = MandatoryLevelSystem;
			integrityString = "System";
			it->integrityString = "System";
			break;
		case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
			integrityLevel = MandatoryLevelSecureProcess;
			integrityString = "Protected";
			it->integrityString = "Protected";
			break;
		default:
			puts(":(");
		}
		
	}

}
void change_integraty(list <info> ::iterator& N,const char* str)
{

			PSID sid;
			const char *sidStr;
            unsigned k=N->num_PID;
            N->integrityString=str;
            if (!strcmp(N->integrityString, "Untrusted"))
			{
				sidStr = "S-1-16-0";
			}
			else
			{
                if (!strcmp(N->integrityString, "Low"))
				{
					sidStr = "S-1-16-4096";
				}
				else
				{
                    if (!strcmp(N->integrityString, "Medium"))
					{
						sidStr = "S-1-16-8192";
					}
					else
					{
                        if (!strcmp(N->integrityString, "High"))
						{
							sidStr = "S-1-16-12288";
						}
						else
						{
                            if (!strcmp(N->integrityString, "System"))
							{
								sidStr = "S-1-16-16384";
							}
							else
							{
								sidStr = "S-1-16-20480";
							}
						}
					}
				}
			}



            ConvertStringSidToSidA((LPSTR)sidStr, &sid);

			DWORD returnLength = 0;

            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, N->num_PID);

			PTOKEN_MANDATORY_LABEL mandatoryLabel = NULL;
			if (hProcess == NULL)
			{
                return;
			}
			OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &hProcess);

			GetTokenInformation(hProcess, TokenIntegrityLevel, NULL, 0, &returnLength);// 902 // c NULL возвращает длину буффера
			mandatoryLabel = (PTOKEN_MANDATORY_LABEL)malloc(returnLength);
			GetTokenInformation(hProcess, TokenIntegrityLevel, mandatoryLabel, returnLength, &returnLength);
			mandatoryLabel->Label.Attributes = SE_GROUP_INTEGRITY;
			mandatoryLabel->Label.Sid = sid;

			SetTokenInformation(hProcess, TokenIntegrityLevel, mandatoryLabel, returnLength);
			CloseHandle(hProcess);
}
