#include "../PE/Instrumentation/materialization/state/pe.hpp"

class PdbParser {
private:
	PeFile			PE_;
	const string& PdbFile;
	struct			FunctionInfos
	{
		string		FuncName;
		ll			FunctionOffset;
		ll			CodeSize;
	};

public:
	explicit				PdbParser(PeFile PE, const string& PdbFile_);
	ll						ProbablyAPdbFile(const string& PdbFile);
	string					FindThePdbPath();
	vector<FunctionInfos>	EnumFunctions();

	~PdbParser() = default;
};
