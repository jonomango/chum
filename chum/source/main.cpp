#include "chum.h"

int main() {
  //auto bin = chum::disassemble("C:\\Users\\realj\\Desktop\\ntoskrnl (19041.1110).exe");
  //auto bin = chum::disassemble("hello-world-x64.dll");
  auto bin = chum::disassemble("hello-world-x64-min.dll");

  if (!bin) {
    std::printf("[!] Failed to disassemble binary.\n");
    return 0;
  }

  bin->print();
}

