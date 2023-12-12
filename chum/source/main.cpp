#include "chum.h"

#include <algorithm>
#include <random>

// Insert a NOP before every instruction.
void insert_nops(chum::binary& bin) {
  for (auto const bb : bin.basic_blocks()) {
    for (std::size_t i = bb->instructions.size(); i > 0; --i)
      bb->insert(bin.instr("\x90"), i - 1);
  }
}

// Add a call at the start of every basic block to an instrumentation function.
void instrument(chum::binary& bin) {
  // Create a basic block.
  auto const block = bin.create_basic_block();
  block->push(bin.instr("\x90")); // NOP
  block->push(bin.instr("\xC3")); // RET

  for (auto const bb : bin.basic_blocks()) {
    if (bb == block)
      continue;

    // All memory references are treated as symbol IDs.
    // CALL block
    bb->insert(bin.instr("\xE8", block));
  }
}

// Shuffle the order of every basic block in the binary.
void shuffle_blocks(chum::binary& bin) {
  auto rd = std::random_device{};
  auto rng = std::default_random_engine{ rd() };
  std::shuffle(std::begin(bin.basic_blocks()), std::end(bin.basic_blocks()), rng);
}

void transform(chum::binary& bin) {
  for (auto const bb : bin.basic_blocks()) {
    for (auto i = bb->instructions.size(); i > 0; --i) {
      auto& instr = bb->instructions[i - 1];

      ZydisDecodedInstruction dinstr = {};
      ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

      // Fully decode the current instruction.
      if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(bin.decoder(),
          instr.bytes, instr.length, &dinstr, operands)))
        continue;

      ZydisEncoderRequest req = {};
      ZydisEncoderDecodedInstructionToEncoderRequest(&dinstr,
        operands, dinstr.operand_count_visible, &req);

      // Split a single ADD instruction into 2 ADDs.
      if (req.mnemonic == ZYDIS_MNEMONIC_ADD && req.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        auto const r = rand();

        // First ADD.
        req.operands[1].imm.s -= r;
        instr = bin.instr(req);

        // Second ADD.
        req.operands[1].imm.s = r;
        bb->insert(bin.instr(req), i);
      }
    }
  }
}

int main(int const argc, char const* const* argv) {
  if (argc < 2) {
    std::printf("Not enough arguments.\n");
    return 0;
  }

  auto bin = chum::disassemble(argv[1]);
  if (!bin) {
    std::printf("Failed to disassemble binary.\n");
    return 0;
  }

  // insert_nops(*bin);
  // instrument(*bin);
  shuffle_blocks(*bin);
  // transform(*bin);

  for (auto const b : bin->create())
    std::printf("%.2X", b);

  return 0;
}

