#include "chum.h"

int main() {
  //auto bin = chum::disassemble("C:\\Users\\realj\\Desktop\\ntoskrnl (19041.1110).exe");
  //auto bin = chum::disassemble("hello-world-x64.dll");
  auto bin = chum::disassemble("hello-world-x64-min.dll");

  if (!bin) {
    std::printf("[!] Failed to disassemble binary.\n");
    return 0;
  }

  auto const bb = bin->create_basic_block("block_1");
  bb->instructions.push_back({ 1, { 0x90 } });
  bb->instructions.push_back({ 6, { 0xFF, 0x15, 0x01, 0x00, 0x00, 0x00 } });

  bin->print();
}

