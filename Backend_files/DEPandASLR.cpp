#define _WIN32_WINNT 0x0602
#include"stllist.h"
#include<tchar.h>
#include <QDebug>

void get_dep_aslr(list <info>& gqlist)
{

	list <info> ::iterator lit;

	for (lit = gqlist.begin(); lit != gqlist.end(); ++lit)
	{
		PROCESS_MITIGATION_DEP_POLICY policy;
		bool k=GetProcessMitigationPolicy(OpenProcess(PROCESS_QUERY_INFORMATION, false, lit->num_PID), ProcessDEPPolicy, &policy, sizeof(policy));
		if (k == 1)
		{
			sprintf(lit->DEP, "%s", "Yes");
		}
		else
		{
			sprintf(lit->DEP, "%s", "No");

		}
		
		PROCESS_MITIGATION_ASLR_POLICY policy1;
        bool k1= GetProcessMitigationPolicy(OpenProcess(PROCESS_QUERY_INFORMATION, false, lit->num_PID), ProcessASLRPolicy, &policy1, sizeof(policy1));
		if (k1 == 1)
		{
			sprintf(lit->ASLR, "%s", "Yes");
		}
		else
		{
			sprintf(lit->ASLR, "%s", "No");

		}
    }

	about_dll(gqlist);
}
void about_dll(list <info>& gqlist)
{
	list <info> ::iterator it;
	HANDLE hSnap;
	
	for (it = gqlist.begin(); it != gqlist.end(); ++it)
	{
		int i = 0;

        // Snapshot of process with heap, modules, threads and so on.
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, it->num_par_PID);
		if (hSnap == NULL)
		{
			continue;
		}
		else
		{
			memset(it->DLL[i], 0, 30);
			MODULEENTRY32 mod;

            //Retrieves information about the first module associated with a process.
			if (Module32First(hSnap, &mod))
			{
                char k1[256]="\0";

				sprintf(k1, "%s", mod.szModule);

				if (!strstr(k1, "exe"))
				{
					sprintf(it->DLL[i], "%s", mod.szModule);
					i++;
                    memset(it->DLL[i], 0, 256);
				}
				
				while (Module32Next(hSnap, &mod))
				{
                    if (strstr(mod.szModule, "exe"))
						continue;
					sprintf(it->DLL[i], "%s", mod.szModule);
					i++;
                    memset(it->DLL[i], 0, 256);
				}
			}

			CloseHandle(hSnap);
		}
	}
}

