#include "chum.h"

int main() {
  //auto bin = chum::disassemble("C:\\Users\\realj\\Desktop\\ntoskrnl (19041.1110).exe");
  //auto bin = chum::disassemble("hello-world-x64.dll");
  auto bin = chum::disassemble("hello-world-x64-min.dll");

  if (!bin) {
    std::printf("[!] Failed to disassemble binary.\n");
    return 0;
  }

  auto const sym = bin->underlying_binary().create_symbol(
    chum::symbol_type::code, "test bb symbol");
  auto const bb = bin->underlying_binary().create_basic_block(sym->id);

  bin->print();
}

