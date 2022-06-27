#include "chum.h"

int main() {
  chum::binary binary;

  if (!binary.load("hello-world-x64.dll")) {
    std::printf("[!] Failed to load binary.\n");
    return 0;
  }

  binary.print();

  // Create data blocks/basic blocks through their constructors, then call
  // binary.append() or binary.insert() to place them in the binary.
  //
  // Disassembly algorithm needs to be worked on.
}

