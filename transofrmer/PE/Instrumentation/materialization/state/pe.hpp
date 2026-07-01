#include <filesystem>
#include <iostream>
#include <fstream>
#include <vector>
#include <ctime>

using namespace std;

namespace _PE
{
	#define TIME_pl(msg, tm)\
		time_t rawtime = tm;\
		cout << msg << ctime(&rawtime) << endl;\

	// so lazy to write uint16_t, lets typedef
	using WORD	= uint16_t;
	using LONG	= uint32_t;
	using ULONG	= uint32_t;
	using UCHAR	= uint8_t;
	using PVOID	= void *;
	namespace fs 	= filesystem;

	#pragma pack(push, 1)

		typedef struct _IMAGE_SECTION_HEADER
		{
		     UCHAR Name[8];
		     ULONG Misc;
		     ULONG VirtualAddress;
		     ULONG SizeOfRawData;
		     ULONG PointerToRawData;
		     ULONG PointerToRelocations;
		     ULONG PointerToLinenumbers;
		     WORD NumberOfRelocations;
		     WORD NumberOfLinenumbers;
		     ULONG Characteristics;
		} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

		typedef struct _IMAGE_FILE_HEADER
		{
		     WORD Machine;
		     WORD NumberOfSections;
		     ULONG TimeDateStamp;
		     ULONG PointerToSymbolTable;
		     ULONG NumberOfSymbols;
		     WORD SizeOfOptionalHeader;
		     WORD Characteristics;
		} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

		typedef struct _IMAGE_DATA_DIRECTORY
		{
		     ULONG VirtualAddress;
		     ULONG Size;
		} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

		typedef struct _IMAGE_OPTIONAL_HEADER
		{
		     WORD Magic;
		     UCHAR MajorLinkerVersion;
		     UCHAR MinorLinkerVersion;
		     ULONG SizeOfCode;
		     ULONG SizeOfInitializedData;
		     ULONG SizeOfUninitializedData;
		     ULONG AddressOfEntryPoint;
		     ULONG BaseOfCode;
		     ULONG BaseOfData;
		     ULONG ImageBase;
		     ULONG SectionAlignment;
		     ULONG FileAlignment;
		     WORD MajorOperatingSystemVersion;
		     WORD MinorOperatingSystemVersion;
		     WORD MajorImageVersion;
		     WORD MinorImageVersion;
		     WORD MajorSubsystemVersion;
		     WORD MinorSubsystemVersion;
		     ULONG Win32VersionValue;
		     ULONG SizeOfImage;
		     ULONG SizeOfHeaders;
		     ULONG CheckSum;
		     WORD Subsystem;
		     WORD DllCharacteristics;
		     ULONG SizeOfStackReserve;
		     ULONG SizeOfStackCommit;
		     ULONG SizeOfHeapReserve;
		     ULONG SizeOfHeapCommit;
		     ULONG LoaderFlags;
		     ULONG NumberOfRvaAndSizes;
		     IMAGE_DATA_DIRECTORY DataDirectory[16];
		} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

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
		     LONG e_lfanew;
		} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

		typedef struct _IMAGE_NT_HEADERS
		{
		     ULONG Signature;
		     IMAGE_FILE_HEADER FileHeader;
		     IMAGE_OPTIONAL_HEADER OptionalHeader;
		} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

	#pragma pack(pop)
}

using namespace _PE;
	
struct PE_
{
	template<typename T> void pe_parse(T PE)
	{
		auto nth_parser = [](T PE) -> PIMAGE_NT_HEADERS
		{
			auto parse_dos = [](T PE) -> PIMAGE_DOS_HEADER
			{
				PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<uint8_t*>(PE.data()));
				cout << "[first 4 bytes] : 0x" << hex << dos->e_magic << endl;
				return dos;
			};
			auto dos = parse_dos(PE);
			auto dos_base = reinterpret_cast<uint8_t*>(dos);
			PIMAGE_NT_HEADERS nth = reinterpret_cast<PIMAGE_NT_HEADERS>(dos_base + dos->e_lfanew);
			cout << "[NT_HEADER signature] : 0x" << nth->Signature << endl;
			cout << "[NumberOfSections] : " << nth->FileHeader.NumberOfSections << endl;
			TIME_pl("[TimeDateStamp] : ", nth->FileHeader.TimeDateStamp);
			return nth;
		};
		auto opth = nth_parser(PE);
	}
};
