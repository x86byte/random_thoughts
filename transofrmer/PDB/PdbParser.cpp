#include "PdbParser.hpp"

ll	PdbExtensionChecker(const string& HFile)
{
	return HFile.ends_with(".pdb");
}

ll	ProbablyAPdbFile(const string& PdbFile)
{
	ifstream file(PdbFile, ios::binary);
	if (!file.is_open())
	{
		cout << "[ERROR] Could not open the file: " << PdbFile << endl;
		return 0;
	}
	vc buffer(sizeof(PDB_SIGNATURE));
	file.read(buffer.data(), sizeof(PDB_SIGNATURE) - 1);
	file.close();
	return strncmp(buffer.data(), PDB_SIGNATURE, sizeof(PDB_SIGNATURE) - 1) == 0;
}

PdbParser::PdbParser(const string& PdbFile_) : PdbFile(PdbFile_)
{
	cout << "[INFO] Parsing the PDB file: " << PdbFile << endl;
}
