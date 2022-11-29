#include "chum.h"

#include <chrono>

void transform(chum::binary& bin) {
  // Create a basic block.
  auto const block = bin.create_basic_block();
  block->push(bin.instr("\x90")); // NOP
  block->push(bin.instr("\xC3")); // RET

  for (auto const bb : bin.basic_blocks()) {
    if (bb == block)
      continue;

    // Insert a CALL to our instrumentation block at the start of every basic block.
    bb->insert(bin.instr("\xE8", block));
  }
}

int main() {
  auto const start_time = std::chrono::high_resolution_clock::now();

  //auto bin = chum::disassemble("C:\\Users\\realj\\Desktop\\dxgkrnl (lizerd).sys");
  //auto bin = chum::disassemble("C:\\Users\\realj\\Desktop\\kernel32.dll");
  auto bin = chum::disassemble("hello-world-x64.dll");
  //auto bin = chum::disassemble("hello-world-x64-min.dll");
  //auto bin = chum::disassemble("split-block-1030.dll");

  auto const end_time = std::chrono::high_resolution_clock::now();

  std::printf("[+] Time elapsed: %zums.\n",
    std::chrono::duration_cast<std::chrono::milliseconds>(
    end_time - start_time).count());

  if (!bin) {
    std::printf("[!] Failed to disassemble binary.\n");
    return 0;
  }

  std::printf("[+] Disassembled binary.\n");

  transform(*bin);

  bin->print();

  if (!bin->create("C:\\Users\\realj\\Desktop\\chum-output.dll")) {
    std::printf("[!] Failed to create output binary.\n");
    return 0;
  }

  std::printf("[+] Created output binary.\n");
}

