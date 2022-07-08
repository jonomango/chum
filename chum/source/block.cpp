#include "block.h"

namespace chum {

// Insert an instruction into the basic block.
void basic_block::insert(instruction const& instr, std::size_t const pos) {
  instructions.insert(begin(instructions) + pos, instr);
}

// Push an instruction to the back of the basic block.
void basic_block::push(instruction const& instr) {
  instructions.push_back(instr);
}

} // namespace chum

