#include "PdbReader.hpp"
#include <PDB.h>
#include <PDB_RawFile.h>
#include <PDB_DBIStream.h>
#include <PDB_ImageSectionStream.h>
#include <PDB_ModuleInfoStream.h>
#include <PDB_ModuleSymbolStream.h>
#include <PDB_PublicSymbolStream.h>
#include <PDB_CoalescedMSFStream.h>
#include <PDB_DBITypes.h>

ll	PdbParser::ProbablyAPdbFile(const string& PdbFile)
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

PdbParser::PdbParser(PeFile PE, const string& PdbFile_) : PE_(PE), PdbFile(PdbFile_) {}

string	PdbParser::FindThePdbPath()
{
	auto& DbgDir = PE_.nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	if (DbgDir.VirtualAddress)
	{
		auto* Img = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(PE_.Raw_.data() + DbgDir.VirtualAddress);
		ll ImgSz = DbgDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
		ll Ctr = 0;
		Const_String PdbPath;
		while (ImgSz--)
		{
			PdbPath = reinterpret_cast<const char*>(PE_.Raw_.data() + Img[Ctr].PointerToRawData + 24);
			if (fs::exists(PdbPath))
				return PdbPath;
			Ctr++;
		}
	}
	if (fs::exists(PdbFile))
		return PdbFile;
	throw Error("[INTERNAL - ERROR] There is no pdb file founded with the Pe file.");
}

vector<PdbParser::FunctionInfos> PdbParser::EnumFunctions()
{
	string pdbPath = FindThePdbPath();
	HANDLE hPdb = CreateFileA(
		pdbPath.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);
	if (hPdb == INVALID_HANDLE_VALUE)
		throw Error("[INTERNAL - ERROR] Could not open the PDB file.");
	DWORD fileSize = GetFileSize(hPdb, nullptr);
	if (!fileSize || fileSize == INVALID_FILE_SIZE)
	{
		CloseHandle(hPdb);
		throw Error("[INTERNAL - ERROR] Could not get the PDB file size.");
	}

	HANDLE hMap = CreateFileMappingA(
		hPdb,
		nullptr,
		PAGE_READONLY,
		0,
		0,
		nullptr
	);
	if (hMap == nullptr)
	{
		CloseHandle(hPdb);
		throw Error("[INTERNAL - ERROR] Could not create a file mapping for the PDB file.");
	}

	const void* pView = MapViewOfFile(
		hMap,
		FILE_MAP_READ,
		0,
		0,
		0
	);
	if (pView == nullptr)
	{
		CloseHandle(hMap);
		CloseHandle(hPdb);
		throw Error("[INTERNAL - ERROR] Could not map the PDB file into memory.");
	}
	vector<PdbParser::FunctionInfos> Functions;
	cout << "[INFO] Enumerating functions from PDB file: " << pdbPath << endl;
	try {
		using namespace PDB;

		const RawFile rawPdbFile(pView);
		const DBIStream dbiStream =
			CreateDBIStream(rawPdbFile); // Dbg info stream

		const ImageSectionStream _ImageSectionStream =
			dbiStream.CreateImageSectionStream(rawPdbFile);
		const ModuleInfoStream _ModuleInfoStream =
			dbiStream.CreateModuleInfoStream(rawPdbFile);
		const CoalescedMSFStream _SymbolRecordStream =
			dbiStream.CreateSymbolRecordStream(rawPdbFile);

	}
	catch (...)
	{
		throw;
	}
	return Functions;
};