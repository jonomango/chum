#include "chum.h"

#include <chrono>

void create_test_binary() {
  chum::binary bin = {};

  // Import a routine from ntdll.dll.
  auto const ntdll = bin.create_import_module("ntdll.dll");
  auto const close_handle = ntdll->create_routine("CloseHandle");
  assert(close_handle->sym_id == 1);

  // Create a basic block that calls the imported routine.
  auto const bb = bin.create_basic_block("basic_block_1");
  bb->instructions.push_back({ 1, { 0x90 } });
  bb->instructions.push_back({ 6, { 0xFF, 0x15, 0x01, 0x00, 0x00, 0x00 } });

  bin.print();
}

int main() {
  //create_test_binary();
  auto const start_time = std::chrono::high_resolution_clock::now();

  auto bin = chum::disassemble("C:\\Users\\realj\\Desktop\\ntoskrnl (19041.1110).exe");
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

  //bin->print();
}

