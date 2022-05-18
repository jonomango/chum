cmake_minimum_required(VERSION 3.9)

project(chum
  DESCRIPTION ""
  HOMEPAGE_URL "https://github.com/jonomango/chum"
  LANGUAGES CXX C
)

# dependencies
add_subdirectory(extern)

# main executable
add_subdirectory(chum)
