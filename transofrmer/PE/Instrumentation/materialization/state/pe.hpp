#include "../../PDB/PdbParser.hpp"

using namespace std;

#pragma region HELPERS

namespace _PE
{
#define TIME_pl(msg, tm)\
		time_t rawtime = tm;\
		cout << msg << ctime(&rawtime) << endl;\

	// so lazy to write uint16_t, lets typedef
	using WORD = uint16_t;
	using VA = uint64_t;
	using RVA = uint32_t;
	using Off = uint32_t;
	using U64 = uint64_t;
	using U32 = uint32_t;
	using i32 = int32_t;
	using UCHAR = uint8_t;
	using BYTE = uint8_t; // damn i forget to write BYTE always instead of UCHAR...
	using PVOID = void*;
	using vui = vector<uint8_t>;
	namespace fs = filesystem;
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
	BYTE		name[9] = {};
	RVA			rva = 0;
	U32			virt_size = 0;
	Off			raw_off = 0;
	U32			raw_size = 0;
	U32			chars = 0;
};

#pragma endregion HERLPERS

#include <array>

struct PeFile
{
	vector<uint8_t>			Raw_;
	vector<uint8_t>			PeImage;
	ll						PeImageSize;
	bool					ispe32plus = false;
	VA						image_base_ = 0;
	RVA						entry_point_ = 0;
	size_t					size_of_image_ = 0;
	PIMAGE_NT_HEADERS64		NtRaw = nullptr;
	vector<SectionInfo>		sections;

	PeFile(fs::path PePath);
	VOID					_IsValidPe();
	VOID					FmtPeInfos();
};
