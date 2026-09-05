#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <vector>
#include <print>
#include <filesystem>
#include <ctime>


#define		all(x) (x).begin(), (x).end()
#define		PDB_SIGNATURE		"Microsoft C/C++ MSF 7.00"
#define		NTOSKRNL_PDB_PATH	"C:\\Dev\\Current\\ent8\\ntoskrnl.pdb"

using		namespace std;
using		ll = long long;
using		vc = vector<char>;
using		ll = long long;

class PdbParser {
private:
	string	PdbFile;
	struct FunctionInfos {
		string		FuncName;
		ll			FunctionOffset;
		ll			CodeSize;
	};

	vector<FunctionInfos> EnumFunctions();
public:
	explicit PdbParser(const string& PdbFile_);
	~PdbParser() = default;
};
