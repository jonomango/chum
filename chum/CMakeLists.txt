add_executable(chum
  "source/main.cpp"
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
