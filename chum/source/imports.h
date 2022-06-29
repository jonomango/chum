#pragma once

#include "symbol.h"

#include <vector>

namespace chum {

struct import_routine {
  // This points to the import symbol for this routine.
  symbol_id sym_id = null_symbol_id;

  // The name of this import.
  std::string name = "";
};

class import_module {
public:
  import_module(class binary& bin, char const* name);

  // Get the null-terminated name of this module.
  char const* name() const;

  // Create a new import routine (and an import symbol!).
  import_routine* create_routine(char const* name);

  // Returns the vector of import routines for this module.
  std::vector<import_routine*> const& routines() const;

private:
  // This is a reference to the binary that this import module is a part of.
  class binary& bin_;

  // This is the list of every imported routine from this module.
  std::vector<import_routine*> routines_ = {};

  // The name of this module.
  std::string name_ = "";
};

} // namespace chum

