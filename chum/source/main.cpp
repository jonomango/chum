#include "chum.h"

int main() {
  chum::binary binary;

  if (!binary.disassemble("hello-world-x64.dll")) {
    std::printf("[!] Failed to disassemble binary.\n");
    return 0;
  }

  std::printf("[+] Disassembled binary.\n");
}

