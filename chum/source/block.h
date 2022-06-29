#pragma once

#include "instruction.h"
#include "symbol.h"

#include <cstdint>
#include <vector>

namespace chum {

// A basic block is a sequence of instructions with a single entry-point and
// a single exit-point. This means that only the first instruction in a basic
// block can be the target of a control-flow instruction (i.e. a CALL) and that
// execution will never transfer into the middle of the block. The last
// instruction in a basic block is the terminating instruction: this halts or
// transfers execution to another basic block (i.e. a RET or JCC). CALL
// instructions are (usually) not considered to be terminating instructions,
// as unintuitive as this may seem. This means that there may be CALLs in
// the middle of a basic block as long as the target function will return.
struct basic_block {
  // The symbol that points to the beginning of this basic block.
  symbol_id sym_id = null_symbol_id;

  // The fallthrough target is the basic block that is immediately after the
  // current block. This is NULL if the terminating instruction will never
  // fall through (RET, JMP, etc). This must be a code symbol.
  symbol_id fallthrough_target = null_symbol_id;

  // The instructions that make up this block. The last instruction is a
  // terminating instruction.
  std::vector<instruction> instructions;
};

// A data block is a contiguous blob of data.
struct data_block {
  // The raw data that makes up this block.
  std::vector<std::uint8_t> bytes = {};

  // The alignment of the starting address for this data block. This value
  // must be a power of 2. A value of 1 indicates no alignment at all.
  std::uint32_t alignment = 1;

  // Whether this data block can be written to once it is mapped in memory.
  bool read_only : 1;
};

} // namespace chum

