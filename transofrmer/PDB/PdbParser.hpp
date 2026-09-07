#include "../PE/Instrumentation/materialization/state/pe.hpp"

class PdbParser {
private:
	PeFile			PE_;
	string			PdbFile;
	struct			FunctionInfos
	{
		string		FuncName;
		ll			FunctionOffset;
		ll			CodeSize;
	};

	vector<FunctionInfos> EnumFunctions();
public:
	explicit		PdbParser(PeFile PE);
	ll				ProbablyAPdbFile(const string& PdbFile);
	~PdbParser() = default;
};
