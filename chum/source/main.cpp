#include "chum.h"

int main() {
  //auto bin = chum::load("C:\\Users\\realj\\Desktop\\ntoskrnl (19041.1110).exe");
  //auto bin = chum::load("hello-world-x64.dll");
  auto bin = chum::load("hello-world-x64-min.dll");

  if (!bin) {
    std::printf("[!] Failed to load binary.\n");
    return 0;
  }

  bin->print();
}

