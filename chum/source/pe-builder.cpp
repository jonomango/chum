#include "pe-builder.h"
#include "binary.h"

#include <fstream>

namespace chum {

// Try to create a PE image at the specified path.
bool pe_builder::create(char const* const path) const {
  auto const contents = create();
  if (contents.empty())
    return false;

  std::ofstream file(path, std::ios::binary);
  if (!file)
    return false;

  file.write(reinterpret_cast<char const*>(contents.data()), contents.size());

  return true;
}

// Create and return the raw contents of a PE image. An empty vector is
// returned on failure.
std::vector<std::uint8_t> pe_builder::create() const {
  // This is the initial file size of the image, before we start adding the
  // raw section data. This value is aligned to the file alignment.
  std::size_t headers_size = 0;

  headers_size += sizeof(IMAGE_DOS_HEADER);
  headers_size += sizeof(IMAGE_NT_HEADERS);

  // Each data block has its own section, while code blocks are all stored
  // in a single section.
  headers_size += sizeof(IMAGE_SECTION_HEADER) * (bin_.data_blocks().size() + 1);

  // Align to the file alignment.
  headers_size = align_integer(headers_size, file_alignment);

  // Allocate a vector with enough space for the MS-DOS header, the PE header,
  // and the section headers.
  std::vector<std::uint8_t> contents(headers_size, 0);

  auto const& data_blocks = bin_.data_blocks();

  // Calculate the virtual section alignment.
  std::uint32_t section_alignment = 1;
  for (auto const& db : data_blocks)
    section_alignment = max(section_alignment, db->alignment);

  std::uint32_t current_virtual_address = static_cast<std::uint32_t>(
    align_integer(contents.size(), section_alignment));

  // Write the raw data of every data block to the vector, as well as
  // their section header info.
  for (std::uint32_t i = 0; i < data_blocks.size(); ++i) {
    auto const& db = data_blocks[i];

    // This pointer has to be computed every time we modify the vector
    // since the underlying buffer could have been re-allocated.
    auto const section = section_header(contents, i);

    // Fill out the section header for this data block.
    std::memset(section, 0, sizeof(*section));
    std::memcpy(section->Name, ".data\0\0\0", 8);
    section->Misc.VirtualSize = static_cast<std::uint32_t>(db->bytes.size());
    section->VirtualAddress   = current_virtual_address;
    section->SizeOfRawData    = static_cast<std::uint32_t>(
      align_integer(db->bytes.size(), file_alignment));
    section->PointerToRawData = static_cast<std::uint32_t>(contents.size());
    section->Characteristics  = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

    if (!db->read_only)
      section->Characteristics |= IMAGE_SCN_MEM_WRITE;

    // Append the raw data of the data block to the vector.
    contents.insert(end(contents), begin(db->bytes), end(db->bytes));

    // Append padding to align the vector to the file alignment value.
    if (contents.size() % file_alignment != 0)
      append_padding(contents, file_alignment - (contents.size() % file_alignment));

    // Increment the current virtual address.
    current_virtual_address = static_cast<std::uint32_t>(
      align_integer(current_virtual_address + db->bytes.size(), section_alignment));
  }

  // The current offset in the code section.
  std::uint32_t instr_offset = 0;

  std::vector<std::uint32_t> sym_to_rva(bin_.symbols().size(), 0);

  sym_to_rva[bin_.entrypoint()->sym_id.value] = current_virtual_address + instr_offset;
  contents.push_back(0xEB);
  contents.push_back(0xFE);
  instr_offset += 2;

  //for (auto const bb : bin_.basic_blocks()) {
  //  sym_to_rva[bb->sym_id.value] = current_virtual_address + instr_offset;

  //  for (auto const& instr : bb->instructions) {
  //    contents.insert(end(contents),
  //      std::begin(instr.bytes), std::begin(instr.bytes) + instr.length);
  //    instr_offset += instr.length;
  //  }

  //  contents.push_back(0xCB);
  //  contents.push_back(0xCB);
  //  contents.push_back(0xCB);
  //  instr_offset += 2;
  //}

  // The code section is the last section (after the data blocks).
  auto const code_section = section_header(contents, data_blocks.size());

  std::memset(code_section, 0, sizeof(*code_section));
  std::memcpy(code_section->Name, ".text\0\0\0", 8);
  code_section->Misc.VirtualSize = instr_offset;
  code_section->VirtualAddress   = current_virtual_address;
  code_section->SizeOfRawData    = static_cast<std::uint32_t>(
    align_integer(instr_offset, file_alignment));
  code_section->PointerToRawData = static_cast<std::uint32_t>(contents.size() - instr_offset);
  code_section->Characteristics  = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

  // Append padding to align the vector to the file alignment value.
  if (contents.size() % file_alignment != 0)
    append_padding(contents, file_alignment - (contents.size() % file_alignment));

  // Align the current virtual address (which is effectively the virtual image size).
  current_virtual_address = static_cast<std::uint32_t>(
    align_integer(current_virtual_address + instr_offset, section_alignment));

  // Write a very minimal MS-DOS header (without the DOS stub).
  auto const dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(contents.data());
  std::memset(dos_header, 0, sizeof(*dos_header));
  dos_header->e_magic  = IMAGE_DOS_SIGNATURE;
  dos_header->e_lfanew = sizeof(*dos_header);

  auto const nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(&contents[sizeof(IMAGE_DOS_HEADER)]);
  write_nt_header(nt_header);

  nt_header->OptionalHeader.AddressOfEntryPoint = sym_to_rva[bin_.entrypoint()->sym_id.value];
  nt_header->OptionalHeader.SectionAlignment    = section_alignment;
  nt_header->OptionalHeader.SizeOfImage         = static_cast<std::uint32_t>(current_virtual_address);
  nt_header->OptionalHeader.SizeOfHeaders       = static_cast<std::uint32_t>(headers_size);

  return contents;
}

// Fill out most of the stuff in the NT header.
void pe_builder::write_nt_header(PIMAGE_NT_HEADERS const nt_header) const {
  std::memset(nt_header, 0, sizeof(*nt_header));
  nt_header->Signature                                  = IMAGE_NT_SIGNATURE;
  nt_header->FileHeader.Machine                         = IMAGE_FILE_MACHINE_AMD64;
  nt_header->FileHeader.NumberOfSections                =
    static_cast<std::uint16_t>(bin_.data_blocks().size() + 1);
  nt_header->FileHeader.SizeOfOptionalHeader            = sizeof(nt_header->OptionalHeader);
  nt_header->FileHeader.Characteristics                 = IMAGE_FILE_EXECUTABLE_IMAGE;
  nt_header->OptionalHeader.Magic                       = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  nt_header->OptionalHeader.ImageBase                   = image_base;
  nt_header->OptionalHeader.FileAlignment               = file_alignment;
  nt_header->OptionalHeader.MajorOperatingSystemVersion = 6;
  nt_header->OptionalHeader.MinorOperatingSystemVersion = 0;
  nt_header->OptionalHeader.MajorSubsystemVersion       = 6;
  nt_header->OptionalHeader.MinorSubsystemVersion       = 0;
  nt_header->OptionalHeader.Subsystem                   = IMAGE_SUBSYSTEM_WINDOWS_CUI;
  nt_header->OptionalHeader.DllCharacteristics          = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    | IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_NO_SEH;
  nt_header->OptionalHeader.SizeOfStackReserve          = 0x10000;
  nt_header->OptionalHeader.SizeOfStackCommit           = 0x1000;
  nt_header->OptionalHeader.SizeOfHeapReserve           = 0x10000;
  nt_header->OptionalHeader.SizeOfHeapCommit            = 0x1000;
  nt_header->OptionalHeader.NumberOfRvaAndSizes         = 16;
}

// Get a pointer to a section header in the vector of bytes.
PIMAGE_SECTION_HEADER pe_builder::section_header(
    std::vector<std::uint8_t>& vec, std::size_t const idx) {
  auto const sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(
    &vec[sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)]);
  return &sections[idx];
}

// Append padding to the vector of bytes.
void pe_builder::append_padding(std::vector<std::uint8_t>& vec,
    std::size_t const count, std::uint8_t const value) {
  vec.insert(end(vec), count, value);
}

// Align an integer up to the specified alignment.
std::uint64_t pe_builder::align_integer(
    std::uint64_t const value, std::uint64_t const alignment) {
  auto const r = value % alignment;

  // Already aligned.
  if (r == 0)
    return value;
  
  return value + (alignment - r);
}

} // namespace chum

