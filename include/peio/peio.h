/**
 * @file peio.h
 * @author Yamane Kazuma
 * @date 2025-10-06
 *
 * @copyright Copyright (c) 2025
 *
 * SPDX-FileCopyrightText: Copyright 2025 Yamane Kazuma
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is licensed under the GNU General Public License v3.0 or later.
 * See <https://www.gnu.org/licenses/> for details.
 */

#ifndef LIBPEIO_PEIO_H__
#define LIBPEIO_PEIO_H__

#include <mio/mmap.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace peio {

enum class Arch {
  I686,
  X86_64,
  NONE,
};

class ImportFunctionEntry {
 private:
  struct OrdinalImportData {
    std::uint32_t ordinal;
  };

  struct NameImportData {
    std::uint16_t hint;
    std::string name;
  };

 public:
  inline ImportFunctionEntry(std::uint32_t ordinal, std::uint32_t rvaIAT) noexcept : rvaIAT_{rvaIAT}, data_{OrdinalImportData{ordinal}} {}
  inline ImportFunctionEntry(std::uint16_t hint, std::string_view name, std::uint32_t rvaIAT) noexcept
      : rvaIAT_{rvaIAT}, data_{NameImportData{hint, std::string{name}}} {}

  inline std::uint32_t rvaIAT() const noexcept {
    return rvaIAT_;
  }

  inline std::optional<std::uint32_t> ordinal() const noexcept {
    auto* p = std::get_if<0>(&data_);
    if (p) {
      return p->ordinal;
    } else {
      return std::nullopt;
    }
  }

  inline std::optional<std::uint16_t> hint() const noexcept {
    auto* p = std::get_if<1>(&data_);
    if (p) {
      return p->hint;
    } else {
      return std::nullopt;
    }
  }

  inline std::optional<std::string_view> name() const noexcept {
    auto* p = std::get_if<1>(&data_);
    if (p) {
      return p->name;
    } else {
      return std::nullopt;
    }
  }

 private:
  std::uint32_t rvaIAT_;
  std::variant<OrdinalImportData, NameImportData> data_;
};

class ModuleEntry {
 public:
  inline ModuleEntry(std::string_view name, std::vector<ImportFunctionEntry>&& functions) noexcept : name_{name}, functions_{functions} {};

  inline const std::string& name() const noexcept {
    return name_;
  }

  inline const std::vector<ImportFunctionEntry>& functions() const noexcept {
    return functions_;
  }

 private:
  std::string name_;
  std::vector<ImportFunctionEntry> functions_;
};

class ExportFunctionEntry {
 private:
  struct ExportData {
    std::uint32_t rva;
  };

  struct ForwardedExportData {
    std::string forwardedTo;
  };

 public:
  inline ExportFunctionEntry(size_t ordinal, std::uint32_t rva, const std::optional<std::string_view>& name, std::uint32_t rvaEAT) noexcept
      : rvaEAT_{rvaEAT}, ordinal_{ordinal}, name_{name ? name.value() : name}, data_{ExportData{rva}} {}

  inline ExportFunctionEntry(size_t ordinal, std::string_view forwardedTo, const std::optional<std::string_view>& name, std::uint32_t rvaEAT) noexcept
      : rvaEAT_{rvaEAT}, ordinal_{ordinal}, name_{name ? name.value() : name}, data_{ForwardedExportData{std::string{forwardedTo}}} {}

  inline std::uint32_t rvaEAT() const noexcept {
    return rvaEAT_;
  }

  inline size_t ordinal() const noexcept {
    return ordinal_;
  }

  inline const std::optional<std::string>& name() const noexcept {
    return name_;
  }

  inline bool isForwarded() const noexcept {
    return (data_.index() == 1);
  }

  inline std::optional<std::uint32_t> rva() const noexcept {
    auto* p = std::get_if<0>(&data_);
    if (p) {
      return p->rva;
    } else {
      return std::nullopt;
    }
  }

  inline std::optional<std::string_view> forwardedTo() const noexcept {
    auto* p = std::get_if<1>(&data_);
    if (p) {
      return p->forwardedTo;
    } else {
      return std::nullopt;
    }
  }

 private:
  std::uint32_t rvaEAT_;
  size_t ordinal_;
  std::optional<std::string> name_;
  std::variant<ExportData, ForwardedExportData> data_;
};

class Pe {
 public:
  explicit Pe(const std::filesystem::path& filepath);

  inline Pe(const Pe&) = delete;
  inline Pe& operator=(const Pe&) = delete;

  inline Pe(Pe&&) = default;
  inline Pe& operator=(Pe&&) = default;

  inline const std::filesystem::path& filepath() const noexcept {
    return filepath_;
  }

  inline Arch arch() const noexcept {
    return arch_;
  }

  const std::vector<ModuleEntry>& imports();
  const std::vector<ModuleEntry>& delayImports();
  const std::vector<ExportFunctionEntry>& exports();

 private:
  std::filesystem::path filepath_;
  mio::mmap_source mmap_;
  Arch arch_;
  std::optional<std::vector<ModuleEntry>> imports_;
  std::optional<std::vector<ModuleEntry>> delayImports_;
  std::optional<std::vector<ExportFunctionEntry>> exports_;

  struct DirectoryEntry {
    std::uint32_t rva;
    std::uint32_t size;
    std::uint32_t offset;
  };

  std::optional<DirectoryEntry> importEntry_;
  std::optional<DirectoryEntry> delayImportEntry_;
  std::optional<DirectoryEntry> exportEntry_;

  inline bool isForwerdedFunction(std::uint32_t funcRva) const noexcept {
    if (!exportEntry_) {
      return false;
    }
    return (exportEntry_->rva <= funcRva) && (funcRva < (exportEntry_->rva + exportEntry_->size));
  }

  struct SectionEntry {
    std::uint32_t rva;
    std::uint32_t size;
    std::uint32_t offset;
  };

  std::vector<SectionEntry> sectionTable_;

  inline std::uint32_t rvaToOffset(std::uint32_t rva) const {
    auto it = std::ranges::upper_bound(sectionTable_, rva, {}, &SectionEntry::rva);
    if (it != sectionTable_.begin()) {
      --it;
      if (it->rva <= rva && rva < it->rva + it->size) {
        return rva - it->rva + it->offset;
      }
    }

    throw std::runtime_error{"Can't resolve virtual address to offset."};
  }

  struct DosHeader {
    std::uint16_t e_magic;
    std::uint16_t e_cblp;
    std::uint16_t e_cp;
    std::uint16_t e_crlc;
    std::uint16_t e_cparhdr;
    std::uint16_t e_minalloc;
    std::uint16_t e_maxalloc;
    std::uint16_t e_ss;
    std::uint16_t e_sp;
    std::uint16_t e_csum;
    std::uint16_t e_ip;
    std::uint16_t e_cs;
    std::uint16_t e_lfarlc;
    std::uint16_t e_ovno;
    std::array<std::uint16_t, 4> e_res;
    std::uint16_t e_oemid;
    std::uint16_t e_oeminfo;
    std::array<std::uint16_t, 10> e_res2;
    std::int32_t e_lfanew;
  };

  struct FileHeader {
    std::uint16_t Machine;
    std::uint16_t NumberOfSections;
    std::uint32_t TimeDateStamp;
    std::uint32_t PointerToSymbolTable;
    std::uint32_t NumberOfSymbols;
    std::uint16_t SizeOfOptionalHeader;
    std::uint16_t Characteristics;
  };

  struct ImageDataDirectory {
    std::uint32_t VirtualAddress;
    std::uint32_t Size;
  };

  struct OptionalHeader32 {
    std::uint16_t Magic;
    std::uint8_t MajorLinkerVersion;
    std::uint8_t MinorLinkerVersion;
    std::uint32_t SizeOfCode;
    std::uint32_t SizeOfInitializedData;
    std::uint32_t SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
    std::uint32_t BaseOfData;
    std::uint32_t ImageBase;
    std::uint32_t SectionAlignment;
    std::uint32_t FileAlignment;
    std::uint16_t MajorOperatingSystemVersion;
    std::uint16_t MinorOperatingSystemVersion;
    std::uint16_t MajorImageVersion;
    std::uint16_t MinorImageVersion;
    std::uint16_t MajorSubsystemVersion;
    std::uint16_t MinorSubsystemVersion;
    std::uint32_t Win32VersionValue;
    std::uint32_t SizeOfImage;
    std::uint32_t SizeOfHeaders;
    std::uint32_t CheckSum;
    std::uint16_t Subsystem;
    std::uint16_t DllCharacteristics;
    std::uint32_t SizeOfStackReserve;
    std::uint32_t SizeOfStackCommit;
    std::uint32_t SizeOfHeapReserve;
    std::uint32_t SizeOfHeapCommit;
    std::uint32_t LoaderFlags;
    std::uint32_t NumberOfRvaAndSizes;
    ImageDataDirectory DataDirectory[16];
  };

  struct OptionalHeader64 {
    std::uint16_t Magic;
    std::uint8_t MajorLinkerVersion;
    std::uint8_t MinorLinkerVersion;
    std::uint32_t SizeOfCode;
    std::uint32_t SizeOfInitializedData;
    std::uint32_t SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
    std::uint64_t ImageBase;
    std::uint32_t SectionAlignment;
    std::uint32_t FileAlignment;
    std::uint16_t MajorOperatingSystemVersion;
    std::uint16_t MinorOperatingSystemVersion;
    std::uint16_t MajorImageVersion;
    std::uint16_t MinorImageVersion;
    std::uint16_t MajorSubsystemVersion;
    std::uint16_t MinorSubsystemVersion;
    std::uint32_t Win32VersionValue;
    std::uint32_t SizeOfImage;
    std::uint32_t SizeOfHeaders;
    std::uint32_t CheckSum;
    std::uint16_t Subsystem;
    std::uint16_t DllCharacteristics;
    std::uint64_t SizeOfStackReserve;
    std::uint64_t SizeOfStackCommit;
    std::uint64_t SizeOfHeapReserve;
    std::uint64_t SizeOfHeapCommit;
    std::uint32_t LoaderFlags;
    std::uint32_t NumberOfRvaAndSizes;
    ImageDataDirectory DataDirectory[16];
  };

  struct ImageSectionHeader {
    std::uint8_t Name[8];
    std::uint32_t VirtualSize;
    std::uint32_t VirtualAddress;
    std::uint32_t SizeOfRawData;
    std::uint32_t PointerToRawData;
    std::uint32_t PointerToRelocations;
    std::uint32_t PointerToLinenumbers;
    std::uint16_t NumberOfRelocations;
    std::uint16_t NumberOfLinenumbers;
    std::uint32_t Characteristics;
  };

  struct ImageImportDescriptor {
    std::uint32_t OriginalFirstThunk;
    std::uint32_t TimeDateStamp;
    std::uint32_t ForwarderChain;
    std::uint32_t Name;
    std::uint32_t FirstThunk;
  };

  struct ImageImportByName {
    std::uint16_t Hint;
    char Name[1];
  };

  struct ImageDelayImportDescriptor {
    std::uint32_t Attributes;
    std::uint32_t DLLName;
    std::uint32_t ModuleHandle;
    std::uint32_t IAT;
    std::uint32_t INT;
    std::uint32_t BoundIAT;
    std::uint32_t UnloadIAT;
    std::uint32_t TimeStamp;
  };

  struct ImageExportDirectory {
    std::uint32_t Characteristics;
    std::uint32_t TimeDateStamp;
    std::uint16_t MajorVersion;
    std::uint16_t MinorVersion;
    std::uint32_t Name;
    std::uint32_t Base;
    std::uint32_t NumberOfFunctions;
    std::uint32_t NumberOfNames;
    std::uint32_t AddressOfFunctions;
    std::uint32_t AddressOfNames;
    std::uint32_t AddressOfNameOrdinals;
  };
};
};  // namespace peio

#ifdef LIBPEIO_HEADER_ONLY
#include "peio/impl/peio.cpp"
#endif  // LIBPEIO_HEADER_ONLY

#endif  // LIBPEIO_PEIO_H__
