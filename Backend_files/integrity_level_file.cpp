#include"stllist.h"
#include <QDebug>

BOOL FileSystemObjectInfo(WCHAR* path, int& integrLvl)
{
  PACL pAcl;
  PSECURITY_DESCRIPTOR sd;

  GetNamedSecurityInfoW(path, SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, &pAcl, &sd);
  if (pAcl == NULL)
  {
    integrLvl = 4;
    qDebug() << "Untrusted";
    return 1;
  }
  DWORD count;
  MANDATORY_LEVEL integrityLevel = MandatoryLevelMedium;
  PCSTR integrityString = NULL;
  if (pAcl)
  {
    ACL_SIZE_INFORMATION saclSize;
    if (!GetAclInformation(pAcl, &saclSize, sizeof(saclSize), AclSizeInformation))
    {
      return FALSE;
    }
    count = saclSize.AceCount;
    for (int i = 0; i < count; i++)
    {
      SYSTEM_MANDATORY_LABEL_ACE *pAce;
      if (!GetAce(pAcl, i, (LPVOID*)&pAce))
      {
        return FALSE;
      }
      if (pAce->Header.AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)
      {
        continue;
      }
      ULONG subAuthority;
      subAuthority = *GetSidSubAuthority((PSID)&pAce->SidStart, 0);
      switch (subAuthority)
      {
      case SECURITY_MANDATORY_LOW_RID:
        integrLvl = 0;
        qDebug() << "Low";
        break;

      case SECURITY_MANDATORY_MEDIUM_RID:
       integrLvl = 1;
        qDebug() << "Medium";
        break;

      case SECURITY_MANDATORY_HIGH_RID:
        integrLvl = 2;
        qDebug() << "High";
        break;

      case SECURITY_MANDATORY_SYSTEM_RID:
        integrLvl = 3;
        qDebug() << "System";
        break;

      default:
        return FALSE;
      }
      break;
    }
  }
}

bool setLevel(WCHAR* path, int lvl)
{
    LPCWSTR INTEGRITY_SDDL_SACL_W = nullptr;
    if (lvl == 0)
        INTEGRITY_SDDL_SACL_W = L"";
    else if (lvl == 1)
        INTEGRITY_SDDL_SACL_W = L"S:(ML;;NW;;;LW)";
    else if (lvl == 2)
        INTEGRITY_SDDL_SACL_W = L"S:(ML;;NW;;;ME)";
    else if (lvl == 3)
        INTEGRITY_SDDL_SACL_W = L"S:(ML;;NW;;;HI)";

    DWORD dwErr = ERROR_SUCCESS;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    PACL pSacl = nullptr;
    BOOL fSaclPresent = FALSE;
    BOOL fSaclDefaulted = FALSE;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(INTEGRITY_SDDL_SACL_W, SDDL_REVISION_1, &pSD, nullptr))
    {
        if (GetSecurityDescriptorSacl(pSD, &fSaclPresent, &pSacl, &fSaclDefaulted))
        {
            dwErr = SetNamedSecurityInfoW(path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, pSacl);
            if (dwErr == ERROR_SUCCESS)
            {
                LocalFree(pSD);
                return true;
            }
            else
            {
                qDebug() << "Error: SetNamedSecurityInfoW, error = " << dwErr;
            }
        }
        LocalFree(pSD);
    }
    else
    {
        qDebug() << "Error: ConvertStringSecurityDescriptorToSecurityDescriptorW, error = " << GetLastError();
    }

    return false;
}
