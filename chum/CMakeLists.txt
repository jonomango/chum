add_executable(chum
  "source/main.cpp"
  "source/chum.h"
  "source/chum.cpp"
  "source/block.h"
  "source/block.cpp"
  "source/instruction.h"
  "source/instruction.cpp"
  "source/util.h"
  "source/util.cpp"
)

# C++17, C11
target_compile_features(chum PRIVATE
  cxx_std_17
  c_std_11
)

# dependencies
target_link_libraries(chum PRIVATE
  Zydis
)
