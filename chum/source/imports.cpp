#include "imports.h"
#include "binary.h"

namespace chum {

import_module::import_module(binary& bin, char const* const name)
    : bin_(bin), name_(name) {}

// Get the null-terminated name of this module.
char const* import_module::name() const {
  return name_.c_str();
}

// Create a new import routine (and an import symbol!).
import_routine* import_module::create_routine(char const* const name) {
  // Create a fancy name for the import symbol.
  char symbol_name[512] = { 0 };
  sprintf_s(symbol_name, "%s.%s", name_.c_str(), name);

  // Create a new import symbol.
  auto const sym = bin_.create_symbol(symbol_type::import, symbol_name);

  // TODO: Make sure this isn't a duplicate.
  sym->ir = routines_.emplace_back(new import_routine());
  sym->ir->sym_id = sym->id;
  sym->ir->name   = name;

  return sym->ir;
}

// Returns the vector of import routines for this module.
std::vector<import_routine*> const& import_module::routines() const {
  return routines_;
}

} // namespace chum

