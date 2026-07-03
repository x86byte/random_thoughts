#include <filesystem>
#include <iostream>
#include <fstream>
#include <vector>
#include <ctime>

using namespace std;

#pragma startreagion HELPERS

namespace _PE
{
	#define TIME_pl(msg, tm)\
		time_t rawtime = tm;\
		cout << msg << ctime(&rawtime) << endl;\

	#define IMAGE_NT_OPTIONAL_HDR32_MAGIC		0x10B
	#define IMAGE_NT_OPTIONAL_HDR64_MAGIC		0x20B
	#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

	// so lazy to write uint16_t, lets typedef
	using WORD	= uint16_t;
	using VA   = uint64_t;
	using RVA  = uint32_t;
	using Off  = uint32_t;
	using U64  = uint64_t;
	using U32  = uint32_t;
	using i32  = int32_t;
	using UCHAR	= uint8_t;
	using BYTE	= uint8_t; // damn i forget an i write BYTE always instead of UCHAR...
	using PVOID	= void *;
	namespace fs 	= filesystem;

	#pragma pack(push, 1)

	typedef struct _IMAGE_SECTION_HEADER {
		UCHAR  Name[8];
		union {
			U32 PhysicalAddress;
			U32 VirtualSize;
		} Misc;
		U32 VirtualAddress;
		U32 SizeOfRawData;
		U32 PointerToRawData;
		U32 PointerToRelocations;
		U32 PointerToLinenumbers;
		WORD  NumberOfRelocations;
		WORD  NumberOfLinenumbers;
		U32 Characteristics;
	} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

		typedef struct _IMAGE_FILE_HEADER
		{
		     WORD Machine;
		     WORD NumberOfSections;
		     U32 TimeDateStamp;
		     U32 PointerToSymbolTable;
		     U32 NumberOfSymbols;
		     WORD SizeOfOptionalHeader;
		     WORD Characteristics;
		} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

		typedef struct _IMAGE_DATA_DIRECTORY
		{
		     U32 VirtualAddress;
		     U32 Size;
		} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

		// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
		typedef struct _IMAGE_OPTIONAL_HEADER64 {
			WORD                 Magic;
			UCHAR                 MajorLinkerVersion;
			UCHAR                 MinorLinkerVersion;
			i32                SizeOfCode;
			i32                SizeOfInitializedData;
			i32                SizeOfUninitializedData;
			i32                AddressOfEntryPoint;
			i32                BaseOfCode;
			U64            ImageBase;
			i32                SectionAlignment;
			i32                FileAlignment;
			WORD                 MajorOperatingSystemVersion;
			WORD                 MinorOperatingSystemVersion;
			WORD                 MajorImageVersion;
			WORD                 MinorImageVersion;
			WORD                 MajorSubsystemVersion;
			WORD                 MinorSubsystemVersion;
			i32                Win32VersionValue;
			i32                SizeOfImage;
			i32                SizeOfHeaders;
			i32                CheckSum;
			WORD                 Subsystem;
			WORD                 DllCharacteristics;
			U64            SizeOfStackReserve;
			U64            SizeOfStackCommit;
			U64            SizeOfHeapReserve;
			U64            SizeOfHeapCommit;
			i32                LoaderFlags;
			i32                NumberOfRvaAndSizes;
			IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
		} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

		typedef struct _IMAGE_DOS_HEADER
		{
		     WORD e_magic;
		     WORD e_cblp;
		     WORD e_cp;
		     WORD e_crlc;
		     WORD e_cparhdr;
		     WORD e_minalloc;
		     WORD e_maxalloc;
		     WORD e_ss;
		     WORD e_sp;
		     WORD e_csum;
		     WORD e_ip;
		     WORD e_cs;
		     WORD e_lfarlc;
		     WORD e_ovno;
		     WORD e_res[4];
		     WORD e_oemid;
		     WORD e_oeminfo;
		     WORD e_res2[10];
		     i32 e_lfanew;
		} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

		typedef struct _IMAGE_NT_HEADERS64 {
			i32 Signature;
			IMAGE_FILE_HEADER FileHeader;
			IMAGE_OPTIONAL_HEADER64 OptionalHeader;
		} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

		// struct SectionInfo
		// {
		// 	char     name[9]   = {};
		// 	RVA      rva       = 0;
		// 	uint32_t virt_size = 0;
		// 	Off      raw_off   = 0;
		// 	uint32_t raw_size  = 0;
		// 	uint32_t chars     = 0;
		//
		// 	bool contains_rva(RVA r) const
		// 	{
		// 		return r >= rva && r < rva + virt_size;
		// 	}
		// 	bool is_code()   const
		// 	{
		// 		return (chars & IMAGE_SCN_CNT_CODE) != 0;
		// 	}
		// 	bool is_exec()   const
		// 	{
		// 		return (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
		// 	}
		// 	bool is_read()   const
		// 	{
		// 		return (chars & IMAGE_SCN_MEM_READ) != 0;
		// 	}
		// 	bool is_write()  const
		// 	{
		// 		return (chars & IMAGE_SCN_MEM_WRITE) != 0;
		// 	}
		// 	bool is_data()   const
		// 	{
		// 		return (chars & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
		// 	}
		// };
	#pragma pack(pop)
}


namespace Helpers
{
	struct Error : runtime_error
	{
		explicit Error(string msg) : runtime_error(msg)
		{
		}
	};
}


using namespace _PE;
using namespace  Helpers;

struct
SectionInfo
{
	BYTE		name[9]   = {};
	RVA			rva       = 0;
	U32			virt_size = 0;
	Off			raw_off   = 0;
	U32			raw_size  = 0;
	U32			chars     = 0;
};

#pragma endregion HERLPERS

#include <array>

struct PE_
{
	bool					ispe32plus		= false;
	VA						image_base_		= 0;
	RVA						entry_point_	= 0;
	size_t					size_of_image_	= 0;
	PIMAGE_NT_HEADERS64		nt64_			= nullptr;
	vector<SectionInfo> sections;
	template<typename T> void pe_infos(T& PE) {
		auto nth_parser = [&](T& PE) -> PIMAGE_NT_HEADERS64
		{
			auto parse_dos = [&](T& PE) -> PIMAGE_DOS_HEADER
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
			PIMAGE_OPTIONAL_HEADER64 oh = &nth->OptionalHeader;
			if (oh->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
				ispe32plus		= true;
			else
				throw Error("[PeImage - ERROR]  not a PE32+ (x64) image - only x64 supported\n");
			image_base_		= oh->ImageBase;
			entry_point_	= oh->AddressOfEntryPoint;
			size_of_image_	= oh->SizeOfImage;
			return nth;
		};
		nt64_ = nth_parser(PE);
		auto parse_sec = [&](T& PE) -> PIMAGE_SECTION_HEADER
		{
			auto sec_info_printer = [&](SectionInfo& si)
			{
				cout << "[SECTION Name]  : " << si.name << endl;
				cout << "[rva]			: " << si.rva << endl;
				cout << "[virt_size]	    : " << si.virt_size << endl;
				cout << "[raw_off]		: " << si.raw_off << endl;
				cout << "[raw_size]		: " << si.raw_size << endl;
				cout << "[chars]		    : " << si.chars << endl;
				cout << endl;
			};
			WORD	num		= nt64_->FileHeader.NumberOfSections;
			size_t	opt_sz	= nt64_->FileHeader.SizeOfOptionalHeader;
			PIMAGE_SECTION_HEADER sh = (PIMAGE_SECTION_HEADER)(reinterpret_cast<uint8_t*>(&nt64_->OptionalHeader) + opt_sz);
			PIMAGE_SECTION_HEADER sh_bp = sh;
			U64 nbr_s = nt64_->FileHeader.NumberOfSections;
			sections.reserve(nbr_s);
			for (int i = 0; i < nbr_s; i++)
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
			return sh;
		}.operator()(PE);
		cout << endl;
		cout << "[nt heaeder 64] : " <<  hex << nt64_ << endl;
		cout << "[image base] : 0x" <<  hex << image_base_ << endl;
	}
};
