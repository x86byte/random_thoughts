#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

template<typename PassT> void RegisterFunctionPass(
	PassBuilder& PB,
	StringRef pn)
{
	PB.registerPipelineParsingCallback(
		[pn](StringRef nm,
			FunctionPassManager& FPM,
			ArrayRef<PassBuilder::PipelineElement>) {

				if (nm != pn)
					return false;

				FPM.addPass(PassT());
				return true;
		});
}

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
	return {
		LLVM_PLUGIN_API_VERSION,
		"ObfDragon",
		LLVM_VERSION_STRING,
		[](PassBuilder& PB)
		{
			RegisterFunctionPass<OptOrbit>(PB, "OptIrOut");
		}
	};
}
