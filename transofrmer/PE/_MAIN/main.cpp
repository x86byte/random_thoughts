#include "../../PDB/PdbParser.hpp"


ll	ExtensionChecker(const string& HFile)
{
	if (HFile.ends_with(".exe"))
		return 1;
	if (HFile.ends_with(".pdb"))
		return 1;
	return 0;
}

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
	return vector{ PdbParser::FunctionInfos{ "", 0, 0 } };
};

/*
PS C:\LLVM\learning\random_thoughts\transofrmer\PE\_MAIN> .\PdbParser.exe "C:\\Dev\\Current\\ent8\\ntoskrnl.pdb"
*/

VOID	PeFile::_IsValidPe()
{
	if (Raw_.size() < sizeof(IMAGE_DOS_HEADER))
		throw Error("[PeFile - ERROR] file too small for DOS header");
	auto* DOS_RAW = reinterpret_cast<PIMAGE_DOS_HEADER>(Raw_.data());
	if (DOS_RAW->e_magic != IMAGE_DOS_SIGNATURE)
		throw Error("[PeFile - ERROR] not a valid PE (bad MZ magic)");
	if (DOS_RAW->e_lfanew <= 0 ||
		(size_t)DOS_RAW->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > Raw_.size())
		throw Error("[PeFile - ERROR] bad e_lfanew offset");
	NtRaw = reinterpret_cast<PIMAGE_NT_HEADERS64>(
		Raw_.data() + DOS_RAW->e_lfanew);
	if (NtRaw->Signature != IMAGE_NT_SIGNATURE)
		throw Error("[PeFile - ERROR] not a valid PE (bad NT signature)");
	//if (NtRaw->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
		// throw Error("[PeFile - ERROR] only AMD64 (x64) binaries are supported");
	PeImageSize = NtRaw->OptionalHeader.SizeOfImage;
	if (PeImageSize == 0)
		throw Error("[PeFile - ERROR] SizeOfImage is zero");
}

PeFile::PeFile(fs::path PePath)
{
	if (!filesystem::exists(PePath))
		throw Error("[PeFile - ERROR] The file does not exist.");
	ifstream PE(PePath, ios::binary);
	if (!PE.is_open())
		throw Error("[PeFile - ERROR] Could not open the file.");
	Raw_.assign(istreambuf_iterator<char>(PE), {});
	_IsValidPe();
	PeImage.assign(PeImageSize, 0);
	U32 HdrBytes = min<U32>(
		NtRaw->OptionalHeader.SizeOfHeaders,
		min<U32>(
			0x1000u,
			(U32)Raw_.size()
		)
	);
	copy_n(
		Raw_.data(),
		HdrBytes,
		PeImage.data()
	);

	for (i32 i = 0; i < NtRaw->FileHeader.NumberOfSections; ++i)
	{
		auto* Section = IMAGE_FIRST_SECTION(NtRaw) + i;
		if (!Section->SizeOfRawData)
			continue;
		if (Section->PointerToRawData + Section->SizeOfRawData > Raw_.size())
			throw Error("[PeFile - ERROR] section raw data exceeds file size");
		if (Section->VirtualAddress + Section->SizeOfRawData > PeImageSize)
			throw Error("[PeFile - ERROR] section virtual address exceeds image size");
		copy_n(
			Raw_.data() + Section->PointerToRawData,
			Section->SizeOfRawData,
			PeImage.data() + Section->VirtualAddress
		);
	}
	DetectArch();
	DetectType();
	// cout << "[First sec name for test] : " << GetSectionIdx(".text") << endl;
}

VOID PeFile::FmtPeInfos() {
	auto nth_parser = [&](vui& PE) -> PIMAGE_NT_HEADERS64
		{
			auto parse_dos = [&](vui& PE) -> PIMAGE_DOS_HEADER
				{
					PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<uint8_t*>(PE.data()));
					cout << "[first 4 bytes] : 0x" << hex << dos->e_magic << endl;
					return dos;
				};
			auto dos = parse_dos(PE);
			auto dos_base = reinterpret_cast<uint8_t*>(dos);
			PIMAGE_NT_HEADERS64 nth = reinterpret_cast<PIMAGE_NT_HEADERS64>(dos_base + dos->e_lfanew);
			cout << "[NT_HEADER signature] : 0x" << hex << nth->Signature << endl;
			cout << "[NumberOfSections] : " << nth->FileHeader.NumberOfSections << endl;
			TIME_pl("[TimeDateStamp] : ", nth->FileHeader.TimeDateStamp);
			{
				PIMAGE_OPTIONAL_HEADER64 oh = &nth->OptionalHeader;
				cout << "[Magic] : " << oh->Magic << endl;
				if (oh->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
				{
					cout << "[PE32+] : true" << endl;
					ispe32plus = true;
				}
				else
				{
					cout << "[PE32+] : false" << endl;
					ispe32plus = false;
				}
				image_base_ = oh->ImageBase;
				entry_point_ = oh->AddressOfEntryPoint;
				size_of_image_ = oh->SizeOfImage;
				return nth;
			}

		};
	NtRaw = nth_parser(PeImage);
	if (!ispe32plus)
		throw Error("[PeImage - ERROR]  not a PE32+ (x64) image - only x64 supported\n");
	cout << "[machine] MACHINE ARCH : " << (arch_() == 0 ? "amd x64-x86" : "UNKNOWN") << " - " << PeType_() << endl;
	cout << "[nt heaeder 64] : " << hex << NtRaw << endl;
	cout << "[image base] : 0x" << hex << image_base_ << endl;
	[&](vui& PE)
		{
			auto sec_info_printer = [&](SectionInfo si)
				{
					cout << "[SECTION Name]  : " << si.name << endl;
					cout << "[rva]			: " << si.rva << endl;
					cout << "[virt_size]	    : " << si.virt_size << endl;
					cout << "[raw_off]		: " << si.raw_off << endl;
					cout << "[raw_size]		: " << si.raw_size << endl;
					cout << "[chars]		    : " << si.chars << endl;
					cout << endl;
				};
			WORD	num = NtRaw->FileHeader.NumberOfSections;
			size_t	opt_sz = NtRaw->FileHeader.SizeOfOptionalHeader;
			PIMAGE_SECTION_HEADER sh = (PIMAGE_SECTION_HEADER)(reinterpret_cast<uint8_t*>(&NtRaw->OptionalHeader) + opt_sz);
			PIMAGE_SECTION_HEADER sh_bp = sh;
			U64 nbr_s = NtRaw->FileHeader.NumberOfSections;
			sections.reserve(nbr_s);
			for (i32 i = 0; i < nbr_s; i++)
			{
				SectionInfo si{};
				copy(begin(sh_bp->Name), end(sh_bp->Name), begin(si.name));
				si.rva = sh_bp->VirtualAddress;
				si.virt_size = sh_bp->Misc.VirtualSize;
				si.raw_off = sh_bp->PointerToRawData;
				si.raw_size = sh_bp->SizeOfRawData;
				si.chars = sh_bp->Characteristics;
				sec_info_printer(si);
				sections.push_back(si);
				sh_bp++;
			}
		}.operator()(PeImage);
	cout << endl;
}

PIMAGE_DOS_HEADER	PeFile::dos()
{
	return (reinterpret_cast<PIMAGE_DOS_HEADER>(PeImage.data()));
}

PIMAGE_NT_HEADERS64	PeFile::nt()
{
	return (reinterpret_cast<PIMAGE_NT_HEADERS64>(PeImage.data() + dos()->e_lfanew));
}


VOID	PeFile::DetectArch()
{
	switch (nt()->FileHeader.Machine)
	{
	case IMAGE_FILE_MACHINE_AMD64:
		ArchType = static_cast<ll>(PeFile::t_arch::x64);
		break;
	case IMAGE_FILE_MACHINE_I386:
		ArchType = static_cast<ll>(PeFile::t_arch::x86);
		break;
	default:
		ArchType = static_cast<ll>(PeFile::t_arch::UNKNOWN); //throw Error("[PeFile - ERROR] the Archeticture not supputed");
		break;
	}
}

VOID PeFile::DetectType()
{
	auto Chars = nt()->FileHeader.Characteristics;
	auto sub = nt()->OptionalHeader.Subsystem;
	if (Chars & IMAGE_FILE_DLL)
		PeType = static_cast<ll>(t_type::DLL);
	else if (Chars & IMAGE_FILE_EXECUTABLE_IMAGE)
		PeType = static_cast<ll>(t_type::EXE);
	else if ((Chars & IMAGE_FILE_SYSTEM) && sub == IMAGE_SUBSYSTEM_NATIVE)
		PeType = static_cast<ll>(t_type::SYS);
	else
		PeType = static_cast<ll>(t_type::UNKNOWN);
	return;
}

ll	PeFile::GetSectionIdx(Const_String SecName)
{
	auto* Head = IMAGE_FIRST_SECTION(nt());
	i32		i = 0;
	for (i = 0; i < nt()->FileHeader.NumberOfSections; i++)
		if (strcmp(reinterpret_cast<char*>(Head[i].Name), SecName) == 0)
			return i;
	return -1;
}

ll	PeFile::arch_()
{
	return ArchType;
}

string	PeFile::PeType_()
{
	ll iTy = PeType;
	if (iTy == 0)
		return "EXE";
	else if (iTy == 1)
		return "DLL";
	else if (iTy == 2)
		return "SYS";
	return "UKNOWN";
}

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
				if (!filesystem::exists(PdbFile))
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
