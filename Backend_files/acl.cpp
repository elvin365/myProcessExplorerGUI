#include"stllist.h"

void acl_ace(list <info_file>& gqlist2, const char* path)
{
    struct info_file fileInfo;

	PSID ownerSid;
	PSID pSid;
	PACL dacl;
	PACL sacl;
	PSECURITY_DESCRIPTOR sd;
	DWORD result;
	
	GetNamedSecurityInfoA(path, SE_FILE_OBJECT, GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, &ownerSid, NULL, &dacl, &sacl, &sd);

	SID_NAME_USE type;
	DWORD strsize = MAX_PATH;
	char ownerDomain[MAX_PATH];
    if (LookupAccountSidA(NULL, ownerSid, fileInfo.owner, &strsize, ownerDomain, &strsize, &type))
	{
		char *sidDisplay;

		ConvertSidToStringSidA(ownerSid, &sidDisplay);
        fileInfo.SID = sidDisplay;
        printf("    Owner   %20s | SID: %50s\n", fileInfo.owner, fileInfo.SID);
	}
	else
	{
        fileInfo.SID = NULL;
        memset(fileInfo.owner, 0, 256);
        memcpy(fileInfo.owner, "NoOwner", strlen("NoOwner"));
	}
	PACL ACL_struct;
	PSECURITY_DESCRIPTOR SecDescrpt;
	if ((GetNamedSecurityInfoA(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &ACL_struct, NULL, &SecDescrpt) == ERROR_SUCCESS))
	{
		if (ACL_struct == NULL)
		{
            sprintf(fileInfo.ACE[0], "%s", "No ACL info");
			return;
		}
		ACL_SIZE_INFORMATION ACL_Info;
		if (GetAclInformation(ACL_struct, &ACL_Info, sizeof(ACL_Info), AclSizeInformation))
		{
			for (DWORD i = 0; i < ACL_Info.AceCount; i++)
			{
				ACCESS_ALLOWED_ACE *ACE = NULL;
				if (GetAce(ACL_struct, i, (LPVOID*)&ACE))
				{
					PSID *pSID = (PSID *)&((ACCESS_ALLOWED_ACE *)ACE)->SidStart;
					wchar_t wUser[MAX_PATH], wDomain[MAX_PATH];
					SID_NAME_USE sidNameUse;
					DWORD dwLen = MAX_PATH;
					if (LookupAccountSidW(NULL, pSID, wUser, (LPDWORD)&dwLen, wDomain, &dwLen, &sidNameUse))
					{
						LPWSTR stringSid = NULL;
						ConvertSidToStringSidW(&ACE->SidStart, &stringSid);
						if ((ACE->Header.AceType == ACCESS_ALLOWED_ACE_TYPE))
						{
                            sprintf(fileInfo.ACE[i], "%s", "Allowed ACE");
							i++;
						}
						if (ACE->Header.AceType == ACCESS_DENIED_ACE_TYPE)
						{
                            sprintf(fileInfo.ACE[i], "%s", "Denied ACE");
							i++;
						}
						if (ACE->Header.AceType == SYSTEM_ALARM_ACE_TYPE)
						{
                            sprintf(fileInfo.ACE[i], "%s", "System Alarm ACE");
							i++;
						}
						if (ACE->Header.AceType == SYSTEM_AUDIT_ACE_TYPE)
						{
                            sprintf(fileInfo.ACE[i], "%s", "System Audit ACE");
							i++;
						}

						if (((ACE)->Mask & WRITE_OWNER) == WRITE_OWNER)
						{
                            sprintf(fileInfo.ACE[i], "%s", "Change Owner");
							i++;
						}
						if ((ACE->Mask& WRITE_DAC) == WRITE_DAC)
						{
                            sprintf(fileInfo.ACE[i], "%s", "Write DAC");
							i++;
						}
						if ((ACE->Mask & DELETE) == DELETE)
						{
                            sprintf(fileInfo.ACE[i], "%s", "Delete");
							i++;
						}
						//this->aclList_.emplace(wUser, L"Delete");
						if ((ACE->Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ)
						{
                            sprintf(fileInfo.ACE[i], "%s", "Read");
							i++;
						}
						if ((ACE->Mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE)
						{
                            sprintf(fileInfo.ACE[i], "%s", "Write");
							i++;
						}
						if ((ACE->Mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE)
						{
                            sprintf(fileInfo.ACE[i], "%s", "Execute");
							i++;
						}
						if ((ACE->Mask  & SYNCHRONIZE) == SYNCHRONIZE)
						{
                            sprintf(fileInfo.ACE[i], "%s", "Synchronize");
							i++;
						}
						if ((ACE->Mask  & READ_CONTROL) == READ_CONTROL)
						{
                            sprintf(fileInfo.ACE[i], "%s", "Read control");
							i++;
						}
					}
				}
			}
		}
	}

    gqlist2.push_back(fileInfo);
}
