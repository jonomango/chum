#include <Zydis/Zydis.h>
#include <cstdio>
#include <vector>
#include <fstream>
#include <Windows.h>

// read all the contents of a file and return the bytes in a vector
std::vector<std::uint8_t> read_file_to_buffer(char const* const path) {
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
std::size_t rva_to_file_offset(PIMAGE_NT_HEADERS const nth, std::size_t const rva) {
  // the section headers are right after the NT header in memory
  auto const sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(nth + 1);

  for (std::size_t i = 0; i < nth->FileHeader.NumberOfSections; ++i) {
    auto const& section = sections[i];

    if (rva >= section.VirtualAddress && rva < (section.VirtualAddress + section.Misc.VirtualSize))
      return (rva - section.VirtualAddress) + section.PointerToRawData;
  }

  return 0;
}

struct code_region {
  // virtual address (not rva!) of the start of the region
  std::size_t virtual_offset;

  // offset in the file
  std::size_t file_offset;

  // size in bytes of the region
  std::size_t size;
};

int main() {
  ZydisDecoder decoder;

  if (ZYAN_FAILED(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
    printf("Failed to initialize Zydis decoder.\n");
    return 0;
  }

  ZydisFormatter formatter;

  if (ZYAN_FAILED(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
    printf("Failed to initialize Zydis formatter.\n");
    return 0;
  }

  ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_BRANCHES, true);
  ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL,   true);
  ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_PRINT_BRANCH_SIZE,       true);

  auto buffer = read_file_to_buffer("./hello-world-x64.dll");

  if (buffer.empty())
    return 0;

  // get the NT header from the DOS header
  auto const dosh = reinterpret_cast<PIMAGE_DOS_HEADER>(&buffer[0]);
  auto const nth  = reinterpret_cast<PIMAGE_NT_HEADERS>(&buffer[dosh->e_lfanew]);

  // the section headers are right after the NT header in memory
  auto const sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(nth + 1);

  // the exception directory (aka the .pdata section) contains an array of functions
  auto const& exception_dir = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
  auto const runtime_functions = reinterpret_cast<PRUNTIME_FUNCTION>(
    &buffer[rva_to_file_offset(nth, exception_dir.VirtualAddress)]);
  auto const runtime_function_count = exception_dir.Size / sizeof(RUNTIME_FUNCTION);

  std::vector<code_region> code_regions;

  // add every non-leaf function as a code region
  for (std::size_t i = 0; i < runtime_function_count; ++i) {
    auto const& func       = runtime_functions[i];

    code_region region = {};
    region.virtual_offset = func.BeginAddress;
    region.file_offset    = rva_to_file_offset(nth, func.BeginAddress);
    region.size           = (func.EndAddress - func.BeginAddress);

    code_regions.push_back(region);
  }

  // TODO: Write a first pass that computes the upper and lower bound sizes,
  //       as well as following external code references.
  for (auto const& region : code_regions) {
    for (std::size_t offset = 0; offset < region.size;) {
      ZydisDecodedInstruction instruction;
      ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

      // decode the current instruction in order to
      // determine if it needs to be "fixed" or not
      auto status = ZydisDecoderDecodeFull(&decoder, &buffer[region.file_offset + offset],
        region.size - offset, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);
      
      if (ZYAN_FAILED(status)) {
        printf("[!] Failed to decode instruction: status=0x%X.\n", status);
        break;
      }

      char formatted_str[256] = { 0 };
      ZydisFormatterFormatInstruction(&formatter, &instruction, operands, instruction.operand_count_visible,
        formatted_str, sizeof(formatted_str), region.virtual_offset + offset + 0x40000000);

      // relocate any relative instructions
      if (instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
        ZydisEncoderRequest enc_request;

        // create a request that will encode the exact same instruction that was decoded
        status = ZydisEncoderDecodedInstructionToEncoderRequest(&instruction,
          operands, instruction.operand_count_visible, &enc_request);

        if (ZYAN_FAILED(status)) {
          printf("[!] Failed to create encoder request: status=0x%X.\n", status);
          break;
        }

        // we want the encoder to automatically use the smallest instruction available
        enc_request.branch_type  = ZYDIS_BRANCH_TYPE_NONE;
        enc_request.branch_width = ZYDIS_BRANCH_WIDTH_NONE;

        // find the operand that causes the instruction to be relative
        for (std::size_t i = 0; i < instruction.operand_count_visible; ++i) {
          auto const& op = operands[i];

          // memory references
          if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            printf("[+] ");

            // sanity check
            if (op.mem.base  != ZYDIS_REGISTER_RIP  ||
                op.mem.index != ZYDIS_REGISTER_NONE ||
                op.mem.scale != 0) {
              printf("[!] Memory operand isn't RIP-relative!\n");
              break;
            }

            // if the destination is +-2GB, then we can just directly modify this instruction
            enc_request.operands[i].mem.displacement = 0x12345678;
          }
          // CALLs, JMPs, etc
          else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
            printf("[-] ");

            // if the destination is +-2GB, then we can just directly modify this instruction
            enc_request.operands[i].imm.s = 0x12345678;
          }
          // this operand doesn't need fixing
          else
            continue;

          std::uint64_t op_abs_addr = 0;

          // expected to fail if this isn't the relative operand
          if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&instruction, &op, region.virtual_offset + offset, &op_abs_addr)))
            continue;

          std::uint8_t encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
          std::size_t instruction_length = ZYDIS_MAX_INSTRUCTION_LENGTH;

          status = ZydisEncoderEncodeInstruction(&enc_request, encoded_instruction, &instruction_length);

          if (ZYAN_FAILED(status)) {
            printf("[!] Failed to encode instruction: status=0x%X.\n", status);
            break;
          }

          printf("[op=%zd] ", i);
          printf("[abs=%zX] ", op_abs_addr);
          printf("[rip=%zX] ", region.virtual_offset + offset);
          printf("[oldb=\'%.2X", buffer[region.file_offset + offset]);
          for (std::size_t j = 1; j < instruction.length; ++j)
            printf(" %.2X", buffer[region.file_offset + offset + j]);
          printf("\'] ");
          printf("[newb=\'%.2X", encoded_instruction[0]);
          for (std::size_t j = 1; j < instruction_length; ++j)
            printf(" %.2X", encoded_instruction[j]);
          printf("\'] ");
          printf("[instr=\'%s\']\n", formatted_str);
        }
      }

      offset += instruction.length;
    }
  }
}
