#include"stllist.h"
void the_username_sid(list <info>&gqlist)
{
	list <info> ::iterator it;
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		if (!it->path)
		{
			it->SID = NULL;
			memset(it->ownerName, 0, 256);
			memcpy(it->ownerName,"NoOwner",strlen("NoOwner"));
			continue;
		}

		PSID ownerSid;
		PSID pSid;
		PACL dacl;
		PACL sacl;
		PSECURITY_DESCRIPTOR sd;

        DWORD result = GetNamedSecurityInfoA(
                                                it->path,
                                                SE_FILE_OBJECT,
                                                GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION ,
                                                &ownerSid,
                                                NULL,
                                                &dacl,
                                                &sacl,
                                                &sd
                                            );
		

		SID_NAME_USE type;
		DWORD strsize = MAX_PATH;

		char ownerDomain[MAX_PATH];
		if (LookupAccountSidA(NULL, ownerSid, it->ownerName, &strsize, ownerDomain, &strsize, &type))
		{
			char *sidDisplay;
			ConvertSidToStringSidA(ownerSid,&sidDisplay);
			it->SID = sidDisplay;
		}
		else
		{
			it->SID = NULL;
			memset(it->ownerName, 0, 256);
			memcpy(it->ownerName, "NoOwner", strlen("NoOwner"));
		}
	}
}
