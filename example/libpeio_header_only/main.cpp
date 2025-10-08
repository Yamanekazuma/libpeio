#include <peio/peio.h>

#include <format>
#include <iostream>
#include <stdexcept>

static inline void print_import_function(const peio::ImportFunctionEntry& f) {
  // {rvaIAT}: <NAME={name}, HINT={hint}|ORDINAL={ordinal}>
  std::cout << std::hex << f.rvaIAT() << ": ";

  auto&& name = f.name();
  if (name) {
    std::cout << "NAME=" << *name;
    auto&& hint = f.hint();
    if (hint) {
      std::cout << ", HINT=" << std::dec << *hint;
    }
  } else {
    auto&& ordinal = f.ordinal();
    if (ordinal) {
      std::cout << "ORDINAL=" << std::dec << *ordinal;
    }
  }

  std::cout << std::endl;
}

static inline void print_export_function(const peio::ExportFunctionEntry& f) {
  // {rvaEAT}: ORDINAL={ordinal}, NAME=<{name}|N/A><, RVA={rva}| -> {forwardedTo}>
  std::cout << std::hex << f.rvaEAT() << ": ORDINAL=" << std::dec << f.ordinal() << ", ";

  auto&& name = f.name();
  if (name) {
    std::cout << "NAME=" << *name;
  } else {
    std::cout << "NAME=N/A";
  }

  if (f.isForwarded()) {
    std::cout << " -> " << *f.forwardedTo();
  } else {
    auto&& rva = f.rva();
    if (rva) {
      std::cout << ", RVA=" << std::hex << *rva;
    }
  }

  std::cout << std::endl;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cout << "Usage: " << argv[0] << " <pefile>" << std::endl;
    return 0;
  }

  try {
    peio::Pe pe{argv[1]};

    std::cout << "filename = " << pe.filepath().string() << std::endl;

    std::cout << "architecture = ";
    switch (pe.arch()) {
      case peio::Arch::I686:
        std::cout << "i686" << std::endl;
        break;
      case peio::Arch::X86_64:
        std::cout << "x86-64" << std::endl;
        break;
      default:
        std::cout << "unknown" << std::endl;
        break;
    }

    auto&& imports = pe.imports();
    std::cout << "imports = ";
    if (imports.empty()) {
      std::cout << "None" << std::endl;
    } else {
      std::cout << "{" << std::endl;
      for (auto&& import : imports) {
        std::cout << "  - " << import.name() << std::endl;
        for (auto&& function : import.functions()) {
          std::cout << "    + ";
          print_import_function(function);
        }
      }
      std::cout << "}" << std::endl;
    }

    auto&& delayImports = pe.delayImports();
    std::cout << "delayImports = ";
    if (delayImports.empty()) {
      std::cout << "None" << std::endl;
    } else {
      std::cout << "{" << std::endl;
      for (auto&& import : delayImports) {
        std::cout << "  - " << import.name() << std::endl;
        for (auto&& function : import.functions()) {
          std::cout << "    + ";
          print_import_function(function);
        }
      }
      std::cout << "}" << std::endl;
    }

    auto&& exports = pe.exports();
    std::cout << "exports = ";
    if (exports.empty()) {
      std::cout << "None" << std::endl;
    } else {
      std::cout << "{" << std::endl;
      for (auto&& function : exports) {
        std::cout << "  - ";
        print_export_function(function);
      }
      std::cout << "}" << std::endl;
    }
  } catch (const std::exception& e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }
}
