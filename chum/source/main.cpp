#include "chum.h"

#include <chrono>

void transform(chum::binary& bin) {
  auto const hello_world_str = bin.create_data_block("Hello world!", 13);
  hello_world_str->read_only = true;

  // Create a symbol to the string.
  auto const hello_world_sym = bin.create_symbol(chum::symbol_type::data);

  // Create a basic block that opens a message box.
  auto const ibb = bin.create_basic_block("instrumentation_block");
  ibb->instructions.push_back({ 1, { 0xCC } }); // INT3
  ibb->instructions.push_back({ 1, { 0xC3 } }); // RET

  for (auto& bb : bin.basic_blocks()) {
    // Dont instrument the instrumentation block...
    if (bb == ibb)
      continue;

    // Insert a CALL to our instrumentation function.
    bb->instructions.insert(begin(bb->instructions),
      chum::instruction::call(ibb));
  }
}

int main() {
  auto const start_time = std::chrono::high_resolution_clock::now();

  //auto bin = chum::disassemble("C:\\Users\\realj\\Desktop\\ntoskrnl (19041.1110).exe");
  auto bin = chum::disassemble("C:\\Users\\realj\\Desktop\\dxgkrnl (lizerd).sys");
  //auto bin = chum::disassemble("hello-world-x64.dll");
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

  //transform(*bin);

  bin->print();
}

