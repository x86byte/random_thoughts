#include "../Instrumentation/materialization/state/pe.hpp"

int main(int ac, char **av)
{
	// if(ac != 2)
	// {
	// 	system("pwd");
	// 	cout << "give a PE to parse\n./pe target.exe\n";
	// 	return 1;
	// }
	fs::path pth("../../bins/h.exe");
	cout << "[PE name] : " << pth << endl;
	ifstream PE(pth, ios::binary);
	if(!PE.is_open())
	{
		throw Error("[INTERNAL ERROR] couldn't open the PE file\n");
		return 1;
	}
	PE.seekg(0, ios::end);
	size_t PE_size = PE.tellg();
	cout << "[PE size] : " << PE_size << endl;
	PE.seekg(0, ios::beg);
	vector<uint8_t> PE_v(PE_size);
	PE.read(reinterpret_cast<char*>(PE_v.data()), PE_size);
	PE_ pe;
	pe.pe_infos<const vector<uint8_t>&>(PE_v);
	return 0;
}
