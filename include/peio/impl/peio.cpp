/**
 * @file peio.cpp
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

#ifndef LIBPEIO_PEIO_CPP__
#define LIBPEIO_PEIO_CPP__

#ifdef LIBPEIO_HEADER_ONLY
#define LIBPEIO_INLINE inline
#else  // LIBPEIO_HEADER_ONLY
#define LIBPEIO_INLINE
#endif  // LIBPEIO_HEADER_ONLY

#include "peio/peio.h"

#include <bit>
#include <fstream>
#include <iostream>
#include <span>
#include <spanstream>
#include <stdexcept>
#include <unordered_map>
#include <utility>

LIBPEIO_INLINE peio::Pe::Pe(const std::filesystem::path& filepath)
    : filepath_{filepath},
      mmap_{filepath.native()},
      arch_{Arch::NONE},
      imports_{std::nullopt},
      exports_{std::nullopt},
      importEntry_{std::nullopt},
      delayImportEntry_{std::nullopt},
      exportEntry_{std::nullopt} {
  size_t offset = 0;

  if (mmap_.size() < sizeof(DosHeader)) {
    throw std::runtime_error{"Failed to read dos header."};
  }

  DosHeader* dosHeader = std::bit_cast<DosHeader*>(mmap_.data());
  offset = sizeof(DosHeader);
  if (dosHeader->e_magic != 0x5A4D) {
    throw std::runtime_error{"MZ magic is wrong."};
  }

  std::uint32_t peMagic = 0;
  if (mmap_.size() < dosHeader->e_lfanew + sizeof(peMagic) + sizeof(FileHeader)) {
    throw std::runtime_error{"Failed to read file header."};
  }
  peMagic = *std::bit_cast<std::uint32_t*>(mmap_.data() + dosHeader->e_lfanew);
  offset = dosHeader->e_lfanew + sizeof(peMagic);
  if (peMagic != 0x00004550) {
    throw std::runtime_error{"PE magic is wrong."};
  }

  FileHeader* fileHeader = std::bit_cast<FileHeader*>(mmap_.data() + offset);
  offset += sizeof(FileHeader);
  switch (fileHeader->Machine) {
    case 0x014C:
      arch_ = Arch::I686;
      break;
    case 0x8664:
      arch_ = Arch::X86_64;
      break;
    default:
      throw std::runtime_error{"Detect unknown machine."};
  }

  ImageDataDirectory* dataDirectory;
  if (arch_ == Arch::I686) {
    if (mmap_.size() < offset + sizeof(OptionalHeader32)) {
      throw std::runtime_error{"Failed to read optional header."};
    }

    OptionalHeader32* optionalHeader = std::bit_cast<OptionalHeader32*>(mmap_.data() + offset);
    offset += sizeof(OptionalHeader32);

    if (optionalHeader->Magic != 0x010B) {
      throw std::runtime_error{"Detect unknown architecture."};
    }

    dataDirectory = optionalHeader->DataDirectory;
  } else {
    if (mmap_.size() < offset + sizeof(OptionalHeader64)) {
      throw std::runtime_error{"Failed to read optional header."};
    }

    OptionalHeader64* optionalHeader = std::bit_cast<OptionalHeader64*>(mmap_.data() + offset);
    offset += sizeof(OptionalHeader64);

    if (optionalHeader->Magic != 0x020B) {
      throw std::runtime_error{"Detect unknown architecture."};
    }

    dataDirectory = optionalHeader->DataDirectory;
  }

  for (size_t i = 0; i < fileHeader->NumberOfSections; ++i) {
    if (mmap_.size() < offset + sizeof(ImageSectionHeader)) {
      throw std::runtime_error{"Failed to read section header."};
    }
    ImageSectionHeader* sectionHeader = std::bit_cast<ImageSectionHeader*>(mmap_.data() + offset);
    offset += sizeof(ImageSectionHeader);

    sectionTable_.emplace_back(sectionHeader->VirtualAddress, sectionHeader->VirtualSize, sectionHeader->PointerToRawData);
  }

  std::ranges::sort(sectionTable_, {}, &SectionEntry::rva);

  if (dataDirectory[0].VirtualAddress == 0 || dataDirectory[0].Size == 0) {
    exports_ = std::make_optional<std::vector<ExportFunctionEntry>>({});
  } else {
    exportEntry_ = DirectoryEntry{dataDirectory[0].VirtualAddress, dataDirectory[0].Size, rvaToOffset(dataDirectory[0].VirtualAddress)};
    if (exportEntry_->size < sizeof(ImageExportDirectory)) {
      throw std::runtime_error{"Image export directory is too small."};
    }
  }

  if (dataDirectory[1].VirtualAddress == 0 || dataDirectory[1].Size == 0) {
    imports_ = std::make_optional<std::vector<ModuleEntry>>({});
  } else {
    importEntry_ = DirectoryEntry{dataDirectory[1].VirtualAddress, dataDirectory[1].Size, rvaToOffset(dataDirectory[1].VirtualAddress)};
    if (importEntry_->size < sizeof(ImageImportDescriptor)) {
      throw std::runtime_error{"Image import directory is too small."};
    }
  }

  if (dataDirectory[13].VirtualAddress == 0 || dataDirectory[13].Size == 0) {
    delayImports_ = std::make_optional<std::vector<ModuleEntry>>({});
  } else {
    delayImportEntry_ = DirectoryEntry{dataDirectory[13].VirtualAddress, dataDirectory[13].Size, rvaToOffset(dataDirectory[13].VirtualAddress)};
    if (delayImportEntry_->size < sizeof(ImageDelayImportDescriptor)) {
      throw std::runtime_error{"Image delay import directory is too small."};
    }
  }
}

LIBPEIO_INLINE const std::vector<peio::ModuleEntry>& peio::Pe::imports() {
  if (imports_) {
    return *imports_;
  }

  if (mmap_.size() < importEntry_->offset + sizeof(ImageImportDescriptor) && mmap_.size() < importEntry_->offset + importEntry_->size) {
    throw std::runtime_error{"Failed to read image import directory."};
  }

  ImageImportDescriptor* importDescriptor = std::bit_cast<ImageImportDescriptor*>(mmap_.data() + importEntry_->offset);

  imports_ = std::vector<ModuleEntry>{};

  while (importDescriptor->FirstThunk != 0) {
    const char* moduleName = mmap_.data() + rvaToOffset(importDescriptor->Name);
    std::vector<ImportFunctionEntry> functions{};

    std::uint32_t rvaIAT = importDescriptor->FirstThunk;
    std::uint32_t* iat = std::bit_cast<std::uint32_t*>(
        mmap_.data() + rvaToOffset(importDescriptor->OriginalFirstThunk != 0 ? importDescriptor->OriginalFirstThunk : importDescriptor->FirstThunk));
    while (*iat != 0) {
      if (((*iat) & 0x80000000) == 0) {
        // import by name
        ImageImportByName* data = std::bit_cast<ImageImportByName*>(mmap_.data() + rvaToOffset(*iat));
        std::uint16_t hint = data->Hint;
        char* name = data->Name;
        functions.emplace_back(hint, name, rvaIAT);
      } else {
        // import by ordinal
        std::uint32_t ordinal = (*iat) & 0x7fffffff;
        functions.emplace_back(ordinal, rvaIAT);
      }

      rvaIAT += sizeof(std::uint32_t);
      ++iat;
    }

    imports_->emplace_back(moduleName, std::move(functions));
    ++importDescriptor;
  }

  return *imports_;
}

LIBPEIO_INLINE const std::vector<peio::ModuleEntry>& peio::Pe::delayImports() {
  if (delayImports_) {
    return *delayImports_;
  }

  if (mmap_.size() < delayImportEntry_->offset + sizeof(ImageDelayImportDescriptor) &&
      mmap_.size() < delayImportEntry_->offset + delayImportEntry_->size) {
    throw std::runtime_error{"Failed to read image delay import directory."};
  }

  ImageDelayImportDescriptor* delayImportDescriptor = std::bit_cast<ImageDelayImportDescriptor*>(mmap_.data() + delayImportEntry_->offset);

  delayImports_ = std::vector<ModuleEntry>{};

  while (delayImportDescriptor->INT != 0) {
    const char* moduleName = mmap_.data() + rvaToOffset(delayImportDescriptor->DLLName);
    std::vector<ImportFunctionEntry> functions{};

    std::uint32_t rvaIAT = delayImportDescriptor->IAT;
    std::uint32_t* INT = std::bit_cast<std::uint32_t*>(mmap_.data() + rvaToOffset(delayImportDescriptor->INT));

    while (*INT != 0) {
      if (((*INT) & 0x80000000) == 0) {
        // import by name
        ImageImportByName* data = std::bit_cast<ImageImportByName*>(mmap_.data() + rvaToOffset(*INT));
        std::uint16_t hint = data->Hint;
        char* name = data->Name;
        functions.emplace_back(hint, name, rvaIAT);
      } else {
        // import by ordinal
        std::uint32_t ordinal = (*INT) & 0x7fffffff;
        functions.emplace_back(ordinal, rvaIAT);
      }

      rvaIAT += sizeof(std::uint32_t);
      ++INT;
    }

    delayImports_->emplace_back(moduleName, std::move(functions));
    ++delayImportDescriptor;
  }

  return *delayImports_;
}

LIBPEIO_INLINE const std::vector<peio::ExportFunctionEntry>& peio::Pe::exports() {
  if (exports_) {
    return *exports_;
  }

  if (mmap_.size() < exportEntry_->offset + sizeof(ImageExportDirectory) && mmap_.size() < exportEntry_->offset + exportEntry_->size) {
    throw std::runtime_error{"Failed to read image export directory."};
  }

  ImageExportDirectory* exportDirectory = std::bit_cast<ImageExportDirectory*>(mmap_.data() + exportEntry_->offset);

  std::unordered_map<size_t, std::string> namesMap{};
  {
    std::uint32_t offsetOfNames = rvaToOffset(exportDirectory->AddressOfNames);
    std::uint32_t offsetOfNameOrdinals = rvaToOffset(exportDirectory->AddressOfNameOrdinals);
    for (size_t i = 0; i < exportDirectory->NumberOfNames; ++i) {
      std::uint16_t nameOrdinal = *std::bit_cast<std::uint16_t*>(mmap_.data() + offsetOfNameOrdinals + i * sizeof(std::uint16_t));
      std::uint32_t offsetOfName = rvaToOffset(*std::bit_cast<std::uint32_t*>(mmap_.data() + offsetOfNames + i * sizeof(std::uint32_t)));
      const char* name = mmap_.data() + offsetOfName;
      namesMap.emplace(nameOrdinal, name);
    }
  }

  exports_ = std::vector<ExportFunctionEntry>{};
  {
    std::uint32_t rvaEAT = exportDirectory->AddressOfFunctions;
    std::uint32_t offsetOfFunctions = rvaToOffset(exportDirectory->AddressOfFunctions);
    size_t ordinalBase = exportDirectory->Base;
    for (size_t i = 0; i < exportDirectory->NumberOfFunctions; ++i) {
      std::uint32_t rvaOfFunction = *std::bit_cast<std::uint32_t*>(mmap_.data() + offsetOfFunctions + i * sizeof(std::uint32_t));

      if (rvaOfFunction == 0) {
        continue;
      }

      size_t ordinal = ordinalBase + i;

      auto it = namesMap.find(i);
      std::optional<std::string_view> name = (it != namesMap.end()) ? std::make_optional<std::string_view>(it->second) : std::nullopt;

      if (isForwerdedFunction(rvaOfFunction)) {
        const char* forwardedTo = mmap_.data() + rvaToOffset(rvaOfFunction);
        exports_->emplace_back(ordinal, forwardedTo, name, rvaEAT);
      } else {
        exports_->emplace_back(ordinal, rvaOfFunction, name, rvaEAT);
      }

      rvaEAT += sizeof(std::uint32_t);
    }
  }

  return *exports_;
}

#endif  // LIBPEIO_PEIO_CPP__
