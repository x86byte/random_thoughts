#include "../Instrumentation/materialization/state/pe.hpp"

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
