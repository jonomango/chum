#include "chum.h"

int main() {
  chum::binary binary;

  auto& db = binary.create_data_block(100);

  db.alignment = 100;
  db.read_only = 1;

  binary.print();

  if (!binary.load("hello-world-x64.dll")) {
    std::printf("[!] Failed to load binary.\n");
    return 0;
  }

  std::printf("[+] Binary loaded.\n");

  binary.print();
}

