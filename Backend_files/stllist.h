#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include<list>
#include<iterator>
#include<iostream>
#include<windows.h>
#include<stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma once

#include<lm.h>
#include<aclapi.h>
#include<sddl.h>
#include<processthreadsapi.h>
#include<winerror.h>
#include<string>


using namespace std;

struct info
{
	 wchar_t name_PID[100]; // the name of process
	 //maybe DWORD not unsigned
    unsigned num_PID;
	 char* path;// the way like C://
	 char par_name[100]; // the name of parent
	unsigned num_par_PID;// the id of the parent
	 char ownerName[256]="\0"; // host/adm/elv
	 char* SID;
	unsigned x_bit;
	char DEP[4];
	char ASLR[4];
    char DLL[1000][256];
	PCSTR integrityString;
};

struct info_file
{
    char owner[256] = "\0";
    char* SID;
    char ACE[100][100] = { "\0","\0" };
};

extern list<info> procInfoList;

void 	get_first_three(list <info>&);
void	exe_path(list <info>&);// get the exe
void	know_your_parent(list <info>&);
void	the_name_of_parent(list <info>&);
void	the_username_sid(list <info>&);
void	x_32_64(list <info>&);
void	get_dep_aslr(list <info>&);
void	about_dll(list <info>&);
void	mandatory_integrity(list <info>&);
void	change_integraty(list <info> ::iterator& iter,const char*);
void	acl_ace(list<info_file>&,const char*);

BOOL FileSystemObjectInfo(WCHAR* path, int& integrLvl);

bool setLevel(WCHAR* path, int lvl);
void moveIterator(list <info> ::iterator& iter, int index);


