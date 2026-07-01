#include "../Instrumentation/materialization/state/pe.hpp"

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

int main(int ac, char **av)
{
	if(ac != 2)
	{
		cout << "give a PE to parse\n./pe target.exe\n";
		return 1;
	}
	fs::path pth(av[1]);
	cout << "[PE name] : " << pth << endl;
	ifstream PE(pth, ios::binary);
	if(!PE.is_open())
	{
		cout << "[INTERNAL ERROR] couldn't open the PE file\n";
		return 1;
	}

	PE.seekg(0, ios::end);
	size_t PE_size = PE.tellg();
	cout << "[PE size] : " << PE_size << endl;
	PE.seekg(0, ios::beg);
	vector<uint8_t> PE_v(PE_size);
	PE.read(reinterpret_cast<char*>(PE_v.data()), PE_size);
	cout << PE_v.size()  << endl;
	PE_ pe;
	pe.pe_parse<const vector<uint8_t>&>(PE_v);
	return 0;
}
