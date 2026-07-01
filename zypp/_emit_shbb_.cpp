#include "../Core/ent8_engine.hpp"
#include "../Materialization/semantic_bridge.hpp"
#include <random>
#include <algorithm>

using namespace obf;
using namespace std;

static bool never_falls_through(const instruction_t& ins)
{
    auto m = ins.zyinstr.info.mnemonic;
    return m == ZYDIS_MNEMONIC_JMP || m == ZYDIS_MNEMONIC_RET;
}

// https://youtu.be/y1lDpZKxtag
bool shuffle_basic_blocks(
    vector<function_t>::iterator& func_iter,
    const FuncAnalysis* fa)
{
    if (func_iter->instructions.size() < 6)
        return false;
    vector<int> instr_block(func_iter->instructions.size(), 0);

    set<int> target_ids;
    for (auto& ins : func_iter->instructions)
        if (ins.has_relative && ins.relative.target_inst_id >= 0)
            target_ids.insert(ins.relative.target_inst_id);

    int bid = 0;
    for (size_t i = 0; i < func_iter->instructions.size(); i++) {
        auto& ins = func_iter->instructions[i];
        if (i > 0 && target_ids.count(ins.inst_id))
            ++bid;
        else if (i > 0 && never_falls_through(func_iter->instructions[i - 1]))
            ++bid;
        else if (i > 0 && ins.runtime_address > 0
                   && func_iter->instructions[i - 1].runtime_address > 0
                   && ins.runtime_address != func_iter->instructions[i - 1].runtime_address
                   && ins.runtime_address > func_iter->instructions[i - 1].runtime_address + 16) {
            ++bid;
        }
        instr_block[i] = bid;
    }
    int num_blocks = bid + 1;
    if (num_blocks < 3)
        return false;

    vector<vector<instruction_t>> block_instrs(num_blocks);
    for (size_t i = 0; i < func_iter->instructions.size(); i++) {
        int b = instr_block[i];
        if (b >= 0 && b < num_blocks)
            block_instrs[b].push_back(move(func_iter->instructions[i]));
    }

    vector<int> order(num_blocks);
    for (int i = 0; i < num_blocks; i++)
        order[i] = i;
    shuffle(order.begin() + 1, order.end(), mt19937(rand()));

    if (debug_shuffle)
        printf("    shuffle '%s': %d blocks", func_iter->name.c_str(), num_blocks);

    vector<instruction_t> new_instrs;
    new_instrs.reserve(func_iter->instructions.size());
    for (int b : order)
        for (auto& ins : block_instrs[b])
            new_instrs.push_back( move(ins));
    func_iter->instructions = move(new_instrs);

    func_iter->inst_id_index.clear();
    for (size_t i = 0; i < func_iter->instructions.size(); i++)
        func_iter->inst_id_index[func_iter->instructions[i].inst_id] = i;

    return true;
}
