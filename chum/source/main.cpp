#include <Zydis/Zydis.h>
#include <cstdio>
#include <vector>
#include <fstream>
#include <queue>
#include <chrono>
#include <Windows.h>

#define CHUM_LOG_SPAM(...) (void)0 //printf(__VA_ARGS__)
#define CHUM_LOG_INFO(...) printf(__VA_ARGS__)
#define CHUM_LOG_WARNING(...) (void)0 //printf(__VA_ARGS__)
#define CHUM_LOG_ERROR(...) printf(__VA_ARGS__)

// TODO: make the code_block structure smaller. size fields can be a single
//       byte each (they're RARELY that big, if ever) and if they happen to
//       overflow, simply split the code block. the file offset can also be
//       derived from the virtual offset (or vise-versa).
struct code_block {
  // the absolute virtual address of this code block after being written to memory
  std::uint8_t* final_virtual_address;

  // virtual offset of this code block in the original binary
  std::uint32_t virtual_offset;

  // file offset in the raw binary
  std::uint32_t file_offset;

  // size of the code block on file
  std::uint32_t file_size;

  // size of the instructions after being written to memory. if not written
  // yet, this is the pessimistic expected size of the code block.
  union {
    std::uint32_t expected_size;
    std::uint32_t final_size;
  };

  // relative code blocks contain a SINGLE instruction that is RIP-relative
  bool is_relative : 1;
};

struct data_block {
  // the absolute virtual address of this data block after being written to memory
  std::uint8_t* final_virtual_address;

  // virtual offset of this data block in the original binary
  std::uint32_t virtual_offset;

  // file offset in the raw binary
  std::uint32_t file_offset;

  // size of the data block on file
  std::uint32_t file_size;

  // size of the data block in virtual memory
  std::uint32_t virtual_size;
};

struct memory_region {
  std::uint8_t* virtual_address;
  std::uint32_t size;
};

// a small utility class for writing instructions to code regions
class code_region_writer {
public:
  // an empty vector may NOT be passed
  code_region_writer(std::vector<memory_region>& regions)
      : regions_(regions), current_region_(&regions[0]) {
    assert(!regions.empty());
  }

  // try to write the specified buffer to the current region,
  // or return false if there isn't enough space.
  bool write(void const* const buffer, std::uint32_t const size) {
    if (current_offset_ + size > current_region_->size)
      return false;

    memcpy(current_region_->virtual_address + current_offset_, buffer, size);
    current_offset_ += size;

    return true;
  }

  // try to write the specified buffer to the current region,
  // or return false if there isn't enough space. if successful,
  // cb.final_virtual_address and cb.final_size will be set accordingly.
  bool write(void const* const buffer, std::uint32_t const size, code_block& cb) {
    if (current_offset_ + size > current_region_->size)
      return false;

    cb.final_virtual_address = current_region_->virtual_address + current_offset_;
    cb.final_size            = size;

    memcpy(cb.final_virtual_address, buffer, size);
    current_offset_ += size;

    return true;
  }

  // try to write the specified buffer to the current region, possibly
  // advancing to the next region is required. false is returned if
  // there are no more regions to advance to. if successful,
  // cb.final_virtual_address and cb.final_size will be set accordingly.
  bool force_write(void const* const buffer, std::uint32_t const size, code_block& cb) {
    while (!write(buffer, size, cb)) {
      if (!advance())
        return false;
    }

    return true;
  }

  // advance to the next region by encoding an unconditional jmp to the start
  // of the next region. this function returns false if there are no more
  // regions to advance to.
  bool advance() {
    // TODO: write this...
    return false;
  }

  // get the address of the current instruction pointer
  std::uint8_t* current_write_address() const {
    return current_region_->virtual_address + current_offset_;
  }

private:
  std::vector<memory_region>& regions_;

  // the current region that we are writing to
  std::size_t current_region_idx_ = 0;
  memory_region* current_region_  = nullptr;

  // the current write offset from the base of the current region
  std::uint32_t current_offset_ = 0;
};

class chum_parser {
public:
  chum_parser(char const* const file_path) {
    // initialize the decoder
    if (ZYAN_FAILED(ZydisDecoderInit(&decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
      CHUM_LOG_ERROR("[!] Failed to initialize Zydis decoder.\n");
      return;
    }

    // initialize the formatter
    if (ZYAN_FAILED(ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL))) {
      CHUM_LOG_ERROR("[!] Failed to initialize Zydis formatter.\n");
      return;
    }

    ZydisFormatterSetProperty(&formatter_, ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_BRANCHES, true);
    ZydisFormatterSetProperty(&formatter_, ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL,   true);
    ZydisFormatterSetProperty(&formatter_, ZYDIS_FORMATTER_PROP_PRINT_BRANCH_SIZE,       true);

    file_buffer_ = read_file_to_buffer(file_path);
    if (file_buffer_.empty()) {
      CHUM_LOG_ERROR("[!] Failed to read file.\n");
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

    if (!parse())
      CHUM_LOG_ERROR("[!] Failed to parse binary.\n");
  }

  // write the new binary to memory
  bool write() {
    if (!write_data_blocks()) {
      CHUM_LOG_ERROR("[!] Failed to write data blocks to memory.\n");
      return false;
    }

    if (!write_code_blocks()) {
      CHUM_LOG_ERROR("[!] Failed to write code blocks to memory.\n");
      return false;
    }

    return true;
  }

  // write each data block to the provided data regions
  bool write_data_blocks() {
    if (data_blocks_.empty())
      return true;

    // index of the data region that we are currently writing to
    std::size_t curr_region_idx = 0;

    // current write offset into the current region
    // TODO: align the current region offset
    std::uint32_t curr_region_offset = 0;

    if (data_regions_.empty()) {
      CHUM_LOG_ERROR("[!] No data regions provided.\n");
      return false;
    }

    for (auto& db : data_blocks_) {
      // the current region we're writing to
      auto const& curr_region = data_regions_[curr_region_idx];

      // amount of space left in the current region
      auto const remaining_region_size = (curr_region.size - curr_region_offset);

      if (db.virtual_size > remaining_region_size) {
        CHUM_LOG_ERROR("[!] Ran out of space in the current data region.\n");
        return false;
      }

      db.final_virtual_address = curr_region.virtual_address + curr_region_offset;

      // fill the data block with 0s
      memset(db.final_virtual_address, 0, db.virtual_size);

      // copy the contents from file to memory
      if (db.file_size > 0) {
        auto const size = min(db.file_size, db.virtual_size);

        memcpy(db.final_virtual_address, &file_buffer_[db.file_offset], size);

        CHUM_LOG_INFO("[+] Copied 0x%.6X data bytes from +0x%.8X to 0x%p.\n",
          size, db.virtual_offset, db.final_virtual_address);
      }

      curr_region_offset += db.virtual_size;

      // TODO: align the current region offset
    }

    return true;
  }

  // write every code block to the provided code regions (while fixing up
  // relative instructions and other annoying things)
  bool write_code_blocks() {
    if (code_blocks_.empty())
      return true;

    if (code_regions_.empty()) {
      CHUM_LOG_ERROR("[!] No code regions provided.\n");
      return false;
    }

    code_region_writer writer(code_regions_);

    for (std::size_t curr_cb_idx = 0; curr_cb_idx < code_blocks_.size(); ++curr_cb_idx) {
      auto& cb = code_blocks_[curr_cb_idx];

      // non-relative instructions can be directly copied
      if (!cb.is_relative) {
        if (!writer.force_write(&file_buffer_[cb.file_offset], cb.file_size, cb)) {
          CHUM_LOG_ERROR("[!] Not enough space in the provided code regions.\n");
          return false;
        }

        CHUM_LOG_SPAM("[+] Copied 0x%X code bytes from +0x%X to 0x%p.\n",
          cb.file_size, cb.virtual_offset, cb.final_virtual_address);

        continue;
      }

      ZydisDecodedInstruction decoded_instruction;
      ZydisDecodedOperand decoded_operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

      // decode the current instruction
      auto status = ZydisDecoderDecodeFull(&decoder_, &file_buffer_[cb.file_offset],
          cb.file_size, &decoded_instruction, decoded_operands,
          ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);

      if (ZYAN_FAILED(status)) {
        CHUM_LOG_ERROR("[!] Failed to decode instruction. Status = 0x%X.\n", status);
        return false;
      }

      assert(decoded_instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE);

      ZydisEncoderRequest encoder_request;

      // create an encoder request from the decoded instruction
      status = ZydisEncoderDecodedInstructionToEncoderRequest(&decoded_instruction,
        decoded_operands, decoded_instruction.operand_count_visible, &encoder_request);

      if (ZYAN_FAILED(status)) {
        CHUM_LOG_ERROR("[!] Failed to create encoder request. Status = 0x%X.\n", status);
        return false;
      }

      std::uint8_t new_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
      std::size_t new_instruction_length = ZYDIS_MAX_INSTRUCTION_LENGTH;

      // branch instructions
      if (decoded_instruction.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE && !(decoded_instruction.attributes & ZYDIS_ATTRIB_HAS_MODRM)) {
        //print_code_block(cb);

        //CHUM_LOG_INFO("[+] Fixing branch instruction.\n");
        //CHUM_LOG_INFO("[+]   Branch type      = %d.\n", encoder_request.branch_type);
        //CHUM_LOG_INFO("[+]   Branch width     = %d.\n", encoder_request.branch_width);
        //CHUM_LOG_INFO("[+]   Catagory type    = %d.\n", decoded_instruction.meta.category);

        auto const delta_ptr = get_instruction_target_delta(&encoder_request, decoded_operands);

        // delta from start of instruction
        std::int64_t delta = *delta_ptr + decoded_instruction.length;

        assert(decoded_instruction.meta.branch_type != ZYDIS_BRANCH_TYPE_FAR);

        // this is the number of prefixes that the new instruction will have
        std::int64_t const prefix_count = __popcnt64(encoder_request.prefixes);

        // this is just used to check if we correctly predicted the instruction length
        std::int64_t predicted_instruction_length = 0;

        auto const is_uncond_jmp = decoded_instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
        auto const is_cond_jmp   = decoded_instruction.meta.category == ZYDIS_CATEGORY_COND_BR;
        auto const is_jmp        = is_uncond_jmp || is_cond_jmp;

        // short relative
        if (is_jmp && std::abs(delta - (prefix_count + 2)) <= 0x7FLL) {
          encoder_request.branch_type = ZYDIS_BRANCH_TYPE_SHORT;
          predicted_instruction_length = prefix_count + 2;
        }
        // near relative (unconditional JMPs/CALLs)
        else if (!is_cond_jmp && std::abs(delta - (prefix_count + 5)) <= 0x7FFF'FFFFLL) {
          encoder_request.branch_type = ZYDIS_BRANCH_TYPE_NEAR;
          predicted_instruction_length = prefix_count + 5;
        }
        // near relative (conditional JMPs)
        else if (is_cond_jmp && std::abs(delta - (prefix_count + 6)) <= 0x7FFF'FFFFLL) {
          encoder_request.branch_type = ZYDIS_BRANCH_TYPE_NEAR;
          predicted_instruction_length = prefix_count + 6;
        }
        // absolute
        else {
          CHUM_LOG_ERROR("[!] Absolute branches not handled yet.\n");
          return false;
        }

        // i dont really know what this field is used for, so let the encoder choose
        encoder_request.branch_width = ZYDIS_BRANCH_WIDTH_NONE;

        // write the new delta now that we know the length of the instruction
        *delta_ptr = delta - predicted_instruction_length;

        status = ZydisEncoderEncodeInstruction(&encoder_request,
          new_instruction, &new_instruction_length);

        if (new_instruction_length != predicted_instruction_length) {
          print_code_block(cb);

          CHUM_LOG_ERROR("[!] Failed to correctly predict branch instruction length.\n");
          CHUM_LOG_ERROR("[!]   Predicted length         = %zd.\n", predicted_instruction_length);
          CHUM_LOG_ERROR("[!]   Real length              = %zu.\n", new_instruction_length);
          CHUM_LOG_ERROR("[!]   Original prefix count    = %u.\n", decoded_instruction.raw.prefix_count);
          CHUM_LOG_ERROR("[!]   Encoder request prefixes = %zX.\n", encoder_request.prefixes);

          CHUM_LOG_ERROR("[!]   New instruction:\n[!]    ");
          for (std::size_t i = 0; i < new_instruction_length; ++i)
            CHUM_LOG_ERROR(" %.2X", new_instruction[i]);
          CHUM_LOG_ERROR("\n");

          return false;
        }
      }
      // memory accesses (probably)
      else {
        status = ZydisEncoderEncodeInstruction(&encoder_request,
          new_instruction, &new_instruction_length);
      }

      if (ZYAN_FAILED(status)) {
        CHUM_LOG_ERROR("[!] Failed to encode relative instruction. Status: 0x%X.\n", status);
        return false;
      }

      if (!writer.force_write(new_instruction,
          static_cast<std::uint32_t>(new_instruction_length), cb)) {
        CHUM_LOG_ERROR("[!] Not enough space in the provided code regions.\n");
        return false;
      }

      CHUM_LOG_SPAM("[+] Encoded a new relative instruction at 0x%p:\n",
        cb.final_virtual_address);
    }

    return true;
  }

  // memory where code will reside (X)
  void add_code_region(void* const virtual_address, std::uint32_t const size) {
    code_regions_.push_back({ static_cast<std::uint8_t*>(virtual_address), size });

    // TODO: make sure the code regions are sorted
  }

  // memory where data will reside (RW)
  void add_data_region(void* const virtual_address, std::uint32_t const size) {
    data_regions_.push_back({ static_cast<std::uint8_t*>(virtual_address), size });
  }

private:
  // populate the code/data blocks that make up the binary
  bool parse() {
    // TODO: add external references to code blocks that are not covered by
    //       exception directory.

    std::size_t decoded_instruction_count = 0;

    // disassemble every function and create a list of code blocks
    for (std::size_t i = 0; i < runtime_funcs_count_; ++i) {
      auto const& runtime_func = runtime_funcs_[i];

      // virtual offset, file offset, and size of the current code block
      auto const block_virt_offset = runtime_func.BeginAddress;
      auto const block_file_offset = rva_to_file_offset(runtime_func.BeginAddress);
      auto const block_size        = (runtime_func.EndAddress - runtime_func.BeginAddress);

      ZydisDecodedInstruction decoded_instruction;

      // create a new code block
      auto cb = &code_blocks_.emplace_back();
      cb->is_relative = false;

      cb->final_virtual_address = 0;
      cb->final_size            = 0;

      cb->virtual_offset = block_virt_offset;
      cb->file_offset    = block_file_offset;
      cb->file_size      = 0;

      // disassemble every instruction in this block
      for (std::uint32_t instruction_offset = 0;
           instruction_offset < block_size;
           instruction_offset += decoded_instruction.length) {
        // pointer to the current instruction in the binary blob
        auto const buffer_curr_instruction = &file_buffer_[block_file_offset + instruction_offset];
        auto const remaining_size = (block_size - instruction_offset);

        // if the current code block is relative, we need to start a new, empty, non-relative one
        if (cb->is_relative) {
          cb = &code_blocks_.emplace_back();
          cb->is_relative = false;

          cb->final_virtual_address = 0;
          cb->final_size            = 0;

          cb->virtual_offset = block_virt_offset + instruction_offset;
          cb->file_offset    = block_file_offset + instruction_offset;
          cb->file_size      = 0;
        }

        // decode the current instruction
        auto const status = ZydisDecoderDecodeInstruction(&decoder_, nullptr,
          buffer_curr_instruction, remaining_size, &decoded_instruction);
        
        // this *really* shouldn't happen but it isn't a fatal error... just
        // ignore any possible remaining instructions in the block.
        if (ZYAN_FAILED(status)) {
          CHUM_LOG_WARNING("[!] Failed to decode instruction!\n");
          CHUM_LOG_WARNING("[!]   Status:               0x%X.\n", status);
          CHUM_LOG_WARNING("[!]   Instruction offset:   0x%X.\n", instruction_offset);
          CHUM_LOG_WARNING("[!]   Block virtual offset: 0x%X.\n", block_virt_offset);
          CHUM_LOG_WARNING("[!]   Block size:           0x%X.\n", block_size);
          CHUM_LOG_WARNING("[!]   Block index:          %zu.\n", i);

          // TODO: directly add the rest of the instructions to the current
          //       (non-relative) code block. it is very likely that we are
          //       dealing with data that has been appended to a function,
          //       and we need to be careful to not throw it away.
          cb->file_size  += remaining_size;
          cb->final_size += remaining_size;

          break;
        }

        ++decoded_instruction_count;

        // non-relative instructions (these can simply be memcpy'd to memory)
        if (!(decoded_instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)) {
          assert(!cb->is_relative);

          cb->file_size  += decoded_instruction.length;
          cb->final_size += decoded_instruction.length;
          continue;
        }

        // we need to end the current code block and create a new empty one
        if (cb->file_size > 0) {
          cb = &code_blocks_.emplace_back();
          cb->is_relative = false;

          cb->final_virtual_address = 0;
          cb->final_size            = 0;

          cb->virtual_offset = block_virt_offset + instruction_offset;
          cb->file_offset    = block_file_offset + instruction_offset;
          cb->file_size      = 0;
        }

        assert(cb->file_size <= 0);

        // change the current (empty) code block into a relative code block
        cb->is_relative    = true;
        cb->file_size     += decoded_instruction.length;

        // TODO: calculate a more accurate expected size
        cb->expected_size += decoded_instruction.length + 32;
      }
    }

    // create a list of data blocks
    for (std::size_t i = 0; i < nt_header_->FileHeader.NumberOfSections; ++i) {
      auto const& section = sections_[i];

      // ignore sections that are executable
      if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
        continue;

      assert(section.Characteristics & IMAGE_SCN_MEM_READ);

      data_block block = {};
      block.final_virtual_address = nullptr;
      block.virtual_offset        = section.VirtualAddress;
      block.file_offset           = section.PointerToRawData;
      block.file_size             = section.SizeOfRawData;
      block.virtual_size          = section.Misc.VirtualSize;

      data_blocks_.push_back(block);
    }

    CHUM_LOG_INFO("[+] Number of runtime functions:    %zu.\n", runtime_funcs_count_);
    CHUM_LOG_INFO("[+] Number of decoded instructions: %zu.\n", decoded_instruction_count);

    CHUM_LOG_INFO("[+] Number of data blocks:          %zu (0x%zX bytes).\n",
      data_blocks_.size(), data_blocks_.size() * sizeof(data_block));

    CHUM_LOG_INFO("[+] Number of code blocks:          %zu (0x%zX bytes).\n",
      code_blocks_.size(), code_blocks_.size() * sizeof(code_block));

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
  std::uint32_t rva_to_file_offset(std::uint32_t const rva) const {
    for (std::size_t i = 0; i < nt_header_->FileHeader.NumberOfSections; ++i) {
      auto const& section = sections_[i];

      if (rva >= section.VirtualAddress && rva < (section.VirtualAddress + section.Misc.VirtualSize))
        return (rva - section.VirtualAddress) + section.PointerToRawData;
    }

    return 0;
  }

  // find the operand that causes an instruction to be "relative" and
  // return a pointer to the operand's target delta.
  static std::int64_t* get_instruction_target_delta(
      ZydisEncoderRequest*       const encoder_request,
      ZydisDecodedOperand const* const decoded_operands) {
    // find the target delta, aka. the value that is added to RIP,
    // which can be either an immediate value or a memory displacement.
    for (std::size_t i = 0; i < encoder_request->operand_count; ++i) {
      auto const& op = decoded_operands[i];

      // memory references
      if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        assert(op.mem.disp.has_displacement);
        assert(op.mem.base  == ZYDIS_REGISTER_RIP);
        assert(op.mem.index == ZYDIS_REGISTER_NONE);
        assert(op.mem.scale == 0);

        return &encoder_request->operands[i].mem.displacement;
      }
      // relative CALLs, JMPs, etc
      else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
        assert(op.imm.is_signed);

        return &encoder_request->operands[i].imm.s;
      }
    }

    return nullptr;
  }

  // calculate the new target delta for a relative instruction. this new delta
  // is relative to the start of the current instruction, rather than the end.
  bool calculate_adjusted_target_delta(
      std::uint8_t const* const current_instruction_address,
      std::size_t         const current_cb_idx,
      std::uint32_t       const target_virtual_offset,
      std::int64_t&             target_delta,
      bool&                     fully_resolved) const {
    // get the current code block (which should be relative)
    auto const& cb = code_blocks_[current_cb_idx];
    assert(cb.is_relative);

    // if the target is in a data block, we can immediately calculate the
    // target delta (even if it is a forward target).
    for (auto const& db : data_blocks_) {
      if (target_virtual_offset < db.virtual_offset ||
          target_virtual_offset >= (db.virtual_offset + db.virtual_size))
        continue;

      auto const target_final_address = db.final_virtual_address +
        (target_virtual_offset - db.virtual_offset);

      target_delta   = target_final_address - current_instruction_address;
      fully_resolved = true;

      CHUM_LOG_SPAM("[+] Calculated data target delta: %c0x%zX.\n",
        "+-"[target_delta < 0 ? 1 : 0], std::abs(target_delta));
      return true;
    }

    // backward targets can also be immediately resolved since their
    // final address has already been determined.
    if (target_virtual_offset <= cb.virtual_offset) {
      // search backwards for the code block that contains the target
      for (std::size_t i = current_cb_idx + 1; i > 0; --i) {
        auto const& cb = code_blocks_[i - 1];

        if (target_virtual_offset < cb.virtual_offset ||
            target_virtual_offset >= (cb.virtual_offset + cb.file_size))
          continue;

        // this is a bit of an edgecase so i'll just handle it when it comes up
        assert(!cb.is_relative);

        auto const target_final_address = cb.final_virtual_address +
          (target_virtual_offset - cb.virtual_offset);

        target_delta   = target_final_address - current_instruction_address;
        fully_resolved = true;

        CHUM_LOG_SPAM("[+] Calculated backward target delta: %c0x%zX.\n",
          "+-"[target_delta < 0 ? 1 : 0], std::abs(target_delta));
        return true;
      }

      // this is possible if the target isn't inside of any known code
      // blocks (i.e. we don't have complete code coverage).
      CHUM_LOG_ERROR("[!] Failed to calculate backward target delta.\n");
      return false;
    }

    target_delta   = 0;
    fully_resolved = false;

    // forward targets can't be immediately resolved, so we're just gonna
    // return the worst-case target delta. this will act as a placeholder
    // until we're able to resolve the real delta.
    for (std::size_t i = current_cb_idx; i < code_blocks_.size(); ++i) {
      auto const& cb = code_blocks_[i];

      target_delta += cb.expected_size;

      if (target_virtual_offset < cb.virtual_offset ||
          target_virtual_offset >= (cb.virtual_offset + cb.file_size))
        continue;

      CHUM_LOG_SPAM("[+] Calculated forward target delta: %c0x%zX.\n",
        "+-"[target_delta < 0 ? 1 : 0], std::abs(target_delta));
      return true;
    }

    // this is possible if the target isn't inside of any known code
    // blocks (i.e. we don't have complete code coverage).
    CHUM_LOG_ERROR("[!] Failed to calculate forward target delta.\n");
    return false;
  }

  std::uint8_t disassemble_and_format(void const* const buffer,
      std::size_t const length, char* const str, std::size_t const str_size) const {
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

    ZydisDecoderDecodeFull(&decoder_, buffer, length, &instruction, operands,
      ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY);
    
    ZydisFormatterFormatInstruction(&formatter_, &instruction, operands,
      instruction.operand_count_visible, str, str_size, ZYDIS_RUNTIME_ADDRESS_NONE);

    return instruction.length;
  }

  void print_code_block(code_block const& cb) const {
    printf("[+] Code block:\n");

    printf("[+]   is_relative    = %d.\n", cb.is_relative);
    printf("[+]   virtual_offset = 0x%X.\n", cb.virtual_offset);
    printf("[+]   file_offset    = 0x%X.\n", cb.file_offset);
    printf("[+]   file_size      = 0x%X.\n", cb.file_size);

    if (cb.is_relative)
      printf("[+]   expected_size  = 0x%X.\n", cb.final_size);

    printf("[+]   instructions:\n");

    std::size_t offset = 0;
    while (offset < cb.file_size) {
      char str[256];
      auto const length = disassemble_and_format(
        &file_buffer_[cb.file_offset + offset], cb.file_size - offset, str, 256);
      
      printf("[+]     +%.3zX: ", offset);
      for (std::size_t i = 0; i < length; ++i)
        printf(" %.2X", file_buffer_[cb.file_offset + offset + i]);
      for (std::size_t i = 0; i < (15 - length); ++i)
        printf("   ");
      printf(" %s.\n", str);

      offset += length;
    }
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

  // this is where the binary will be written to
  std::vector<memory_region> code_regions_ = {};
  std::vector<memory_region> data_regions_ = {};

  // blocks of code/data that make up the binary
  std::vector<code_block> code_blocks_ = {};
  std::vector<data_block> data_blocks_ = {};
};

int main() {
  auto const start_time = std::chrono::high_resolution_clock::now();

  chum_parser chum("C:/Windows/system32/ntoskrnl.exe");
  chum.add_code_region(VirtualAlloc(nullptr, 0x1'000'000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE), 0x1'000'000);
  chum.add_data_region(VirtualAlloc(nullptr, 0x1'000'000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE),         0x1'000'000);

  //chum_parser chum("./hello-world-x64.dll");
  //chum.add_code_region(VirtualAlloc(nullptr, 0x4000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE), 0x4000);
  //chum.add_data_region(VirtualAlloc(nullptr, 0x4000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE),         0x4000);

  if (!chum.write())
    CHUM_LOG_ERROR("[!] Failed to write binary to memory.\n");

  auto const end_time = std::chrono::high_resolution_clock::now();

  CHUM_LOG_INFO("[+] Time elapsed: %zums\n", std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());
}
