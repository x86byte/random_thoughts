#include "../../PDB/PdbReader.hpp"


ll	ExtensionChecker(const string& HFile)
{
	if (HFile.ends_with(".exe"))
		return 1;
	if (HFile.ends_with(".pdb"))
		return 1;
	return 0;
}
// ========================================================================
/*
PS C:\LLVM\learning\random_thoughts\transofrmer\PE\_MAIN> .\PdbParser.exe "C:\\Dev\\Current\\ent8\\ntoskrnl.pdb"
*/

i32 main(i32 ac, i8* av[])
{
	try {
		if (ac == 3)
		{
			string PePath = string((const char*)(av[2]));
			if (!ExtensionChecker(PePath))
			{
				cout << "[ERROR] The file must have a .exe extension." << endl;
				return 1;
			}
			fs::path pth(PePath);
			cout << "[PE name] : " << pth << endl;
			PeFile pe(pth);
			pe.FmtPeInfos();
			string PdbFile = string((const char*)(av[1]));
			if (ExtensionChecker(PdbFile))
			{
				if (!fs::exists(PdbFile))
				{
					cout << "[ERROR] The file does not exist." << endl;
					return 1;
				}
				PdbParser PdbParser_(pe, PdbFile);
				PdbParser_.FindThePdbPath();
				if (!PdbParser_.ProbablyAPdbFile(PdbFile))
				{
					cout << "[ERROR] The file does not appear to be a valid PDB file." << endl;
					return 1;
				}
				PdbParser_.EnumFunctions();
			}
			else {
				cout << "[ERROR] The file must have a .pdb extension." << endl;
				return 1;
			}
		}
		else
		{
			cout << "Usage: " << av[0] << " <file.pdb> <file.exe>" << endl;
			return 1;
		}
	}
	catch (const exception& e) {
		cout << "[INTERNAL ERROR] Exception: " << e.what() << endl;
		return 1;
	}
	return 0;
}
