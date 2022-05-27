#include <Zydis/Zydis.h>
#include <cstdio>
#include <vector>
#include <fstream>
#include <Windows.h>

class chum_parser {
public:
  chum_parser(char const* const file_path) {
    // initialize the decoder
    if (ZYAN_FAILED(ZydisDecoderInit(&decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
      printf("[!] Failed to initialize Zydis decoder.\n");
      return;
    }

    // initialize the formatter
    if (ZYAN_FAILED(ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL))) {
      printf("[!] Failed to initialize Zydis formatter.\n");
      return;
    }

    ZydisFormatterSetProperty(&formatter_, ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_BRANCHES, true);
    ZydisFormatterSetProperty(&formatter_, ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL,   true);
    ZydisFormatterSetProperty(&formatter_, ZYDIS_FORMATTER_PROP_PRINT_BRANCH_SIZE,       true);

    file_buffer_ = read_file_to_buffer(file_path);
    if (file_buffer_.empty()) {
      printf("[!] Failed to read file.\n");
      return;
    }

    dos_header_ = reinterpret_cast<PIMAGE_DOS_HEADER>(&file_buffer_[0]);
    nt_header_  = reinterpret_cast<PIMAGE_NT_HEADERS>(&file_buffer_[dos_header_->e_lfanew]);
    sections_   = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_header_ + 1);

    // the exception directory (aka the .pdata section) contains an array of functions
    auto const& exception_dir = nt_header_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    runtime_funcs_ = reinterpret_cast<PRUNTIME_FUNCTION>(
      &file_buffer_[rva_to_file_offset(exception_dir.VirtualAddress)]);
    runtime_funcs_count_ = exception_dir.Size / sizeof(RUNTIME_FUNCTION);

    if (!parse()) {
      printf("[!] Failed to parse binary.\n");
      return;
    }
  }

private:
  // the real "meat" of the parser
  bool parse() {
    // TODO: add external references to code regions that are not covered by
    //       exception directory.

    // disassemble every function and create a list of instructions that
    // will need to be fixed later on.
    for (std::size_t i = 0; i < runtime_funcs_count_; ++i) {
      auto const& runtime_func = runtime_funcs_[i];

      // virtual offset, file offset, and size of the current code region
      auto const region_virt_offset = runtime_func.BeginAddress;
      auto const region_file_offset = rva_to_file_offset(runtime_func.BeginAddress);
      auto const region_size        = (runtime_func.EndAddress - runtime_func.BeginAddress);

      // disassemble every instruction in this region
      for (std::size_t instruction_offset = 0; instruction_offset < region_size;) {
        ZydisDecodedInstruction decoded_instruction;
        ZydisDecodedOperand decoded_operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

        // pointer to the current instruction in the binary blob
        auto const buffer_curr_instruction = &file_buffer_[region_file_offset + instruction_offset];
        auto const remaining_size = (region_size - instruction_offset);

        // decode the current instruction
        auto const status = ZydisDecoderDecodeFull(&decoder_, buffer_curr_instruction,
          remaining_size, &decoded_instruction, decoded_operands,
          ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);
        
        // this *really* shouldn't happen but it isn't a fatal error... just
        // ignore any possible remaining instructions in the region.
        if (ZYAN_FAILED(status)) {
          printf("[!] Failed to decode instruction! VA=0x%zX. Status=0x%X.\n",
            region_virt_offset + instruction_offset, status);
          break;
        }

        printf("[+] Decoded instruction. VA=0x%zX. Length=0x%X.\n",
          region_virt_offset + instruction_offset, decoded_instruction.length);

        // proceed to the next contiguous instruction
        instruction_offset += decoded_instruction.length;
      }
    }

    return true;
  }

  // read all the contents of a file and return the bytes in a vector
  static std::vector<std::uint8_t> read_file_to_buffer(char const* const path) {
    // open the file
    std::ifstream file(path, std::ios::binary);
    if (!file)
      return {};

    // get the size of the file
    file.seekg(0, file.end);
    std::vector<std::uint8_t> contents(file.tellg());
    file.seekg(0, file.beg);

    // read
    file.read((char*)contents.data(), contents.size());

    return contents;
  }

  // convert an RVA offset to a file offset
  std::size_t rva_to_file_offset(std::size_t const rva) const {
    for (std::size_t i = 0; i < nt_header_->FileHeader.NumberOfSections; ++i) {
      auto const& section = sections_[i];

      if (rva >= section.VirtualAddress && rva < (section.VirtualAddress + section.Misc.VirtualSize))
        return (rva - section.VirtualAddress) + section.PointerToRawData;
    }

    return 0;
  }

private:
  // zydis
  ZydisDecoder decoder_     = {};
  ZydisFormatter formatter_ = {};

  // raw binary blob of the PE file
  std::vector<std::uint8_t> file_buffer_ = {};

  // pointers into the file buffer
  PIMAGE_DOS_HEADER dos_header_   = nullptr;
  PIMAGE_NT_HEADERS nt_header_    = nullptr;
  PIMAGE_SECTION_HEADER sections_ = nullptr;

  // exception directory
  PRUNTIME_FUNCTION runtime_funcs_ = nullptr;
  std::size_t runtime_funcs_count_ = 0;
};

int main() {
  chum_parser chum("./hello-world-x64.dll");
}
