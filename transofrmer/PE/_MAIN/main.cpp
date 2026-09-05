#include "../Instrumentation/materialization/state/pe.hpp"

ll	ExtensionChecker(const string& HFile)
{
	if (HFile.ends_with(".exe"))
		return 1;
	if (HFile.ends_with(".pdb"))
		return 1;
	return 0;
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

/*
PS C:\LLVM\learning\random_thoughts\transofrmer\PE\_MAIN> .\PdbParser.exe "C:\\Dev\\Current\\ent8\\ntoskrnl.pdb"
*/

PeFile::PeFile(fs::path PePath)
{
	if (!filesystem::exists(PePath))
	{
		cout << "[ERROR] The file does not exist." << endl;
		throw Error("[PeFile - ERROR] The file does not exist.");
	}
	ifstream PE(PePath, ios::binary);
	if (!PE.is_open())
	{
		cout << "[ERROR] Could not open the file: " << PePath << endl;
		throw Error("[PeFile - ERROR] Could not open the file.");
	}
	PE.seekg(0, ios::end);
	size_t PE_size = PE.tellg();
	cout << "[PE size] : " << PE_size << endl;
	PE.seekg(0, ios::beg);
	vector<uint8_t> PE_v(PE_size);
	PE.read(reinterpret_cast<char*>(PE_v.data()), PE_size);
	PE.close();
	PeImage = move(PE_v);
	PeImageSize = PE_size;
}

int main(int ac, char* av[])
{
	try {
		if (ac == 3)
		{
			string PePath = av[2];
			if (!ExtensionChecker(PePath))
			{
				cout << "[ERROR] The file must have a .exe extension." << endl;
				return 1;
			}
			fs::path pth(PePath);
			cout << "[PE name] : " << pth << endl;
			PeFile pe(pth);
			pe.pe_infos();
			string PdbFile = av[1];
			if (!ExtensionChecker(PdbFile))
			{
				if (!filesystem::exists(PdbFile))
				{
					cout << "[ERROR] The file does not exist." << endl;
					return 1;
				}
				if (!ProbablyAPdbFile(PdbFile))
				{
					cout << "[ERROR] The file does not appear to be a valid PDB file." << endl;
					return 1;
				}
				PdbParser PdbParser_(PdbFile);
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
