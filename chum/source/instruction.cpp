#include "instruction.h"
#include "block.h"

namespace chum {

// Create a CALL instruction to the specified basic block.
instruction instruction::call(basic_block const* const bb) {
  return instruction({
    0xE8,
    (bb->sym_id >>  0) & 0xFF,
    (bb->sym_id >>  8) & 0xFF,
    (bb->sym_id >> 16) & 0xFF,
    (bb->sym_id >> 24) & 0xFF
  });
}

} // namespace chum

