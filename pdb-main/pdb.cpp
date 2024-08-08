#include "pch.h"
#include "base64.h"

bool GetDBGGuid(const char* path, std::string& Guid, std::string& Name)
{
    HANDLE hFile = nullptr;
    HANDLE hMemMap = nullptr;
    PVOID pImageBase = nullptr;

    PIMAGE_DEBUG_DIRECTORY DebugDirectory = nullptr;
    ULONG DirectorySize = 0;
    PDBINFO PDB = { 0 };

    CHAR PDBGUID[64] = { 0 };

    PVOID OldValue = NULL;
    Wow64DisableWow64FsRedirection(&OldValue);

    hFile = ::CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        Wow64RevertWow64FsRedirection(OldValue);
        return false;
    }
    hMemMap = ::CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMemMap)
    {
        Wow64RevertWow64FsRedirection(OldValue);
        return false;
    }
    pImageBase = ::MapViewOfFile(hMemMap, FILE_MAP_READ, 0, 0, 0);
    if (!pImageBase)
    {
        Wow64RevertWow64FsRedirection(OldValue);
        return false;
    }

    DebugDirectory = (PIMAGE_DEBUG_DIRECTORY)ImageDirectoryEntryToData(
        (PVOID)pImageBase,
        FALSE,
        IMAGE_DIRECTORY_ENTRY_DEBUG,
        &DirectorySize
    );

    RtlCopyMemory(&PDB, (PCHAR)pImageBase + DebugDirectory->PointerToRawData, sizeof(PDB));

    wsprintfA(
        PDBGUID, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
        PDB.UID.Data1, PDB.UID.Data2, PDB.UID.Data3,
        PDB.UID.Data4[0], PDB.UID.Data4[1], PDB.UID.Data4[2],
        PDB.UID.Data4[3], PDB.UID.Data4[4], PDB.UID.Data4[5],
        PDB.UID.Data4[6], PDB.UID.Data4[7], PDB.Age
    );

    Guid = std::string(PDBGUID);
    Name = std::string(PDB.PDBFileName);

    if (pImageBase)
        UnmapViewOfFile(pImageBase);
    if (hMemMap)
        CloseHandle(hMemMap);
    if (hFile)
        CloseHandle(hFile);

    Wow64RevertWow64FsRedirection(OldValue);
    return true;
}

bool HttpGet(const char* url, PVOID recvbuf, int len) {
    HINTERNET InternetHandle = nullptr;
    HINTERNET hSession = nullptr;
    ULONG Number = 0;
    bool result = false;

    hSession = InternetOpenA("", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hSession != NULL)
    {
        InternetHandle = InternetOpenUrlA(hSession, url, NULL, 0, INTERNET_FLAG_DONT_CACHE, 0);
        if (InternetHandle != NULL)
        {
            result = InternetReadFile(InternetHandle, recvbuf, len, &Number);
            InternetCloseHandle(InternetHandle);
        }
        InternetCloseHandle(hSession);
    }

    return result;
}

UINT32 GetServceFuncAddress(const char* Guid, const char* Name, const char* FuncName)
{
    UINT32 result = 0;

    auto url = std::string("http://") + std::string(SERVICE_IP) + std::string(":") + std::string(SERVICE_PORT) + std::string("/GetSymbols/") +
        std::string(Name) + std::string("/") + std::string(Guid) + std::string("/nostruct/null/null/") + std::string(FuncName);

    CHAR TempBuf[MAX_PATH] = { 0 };
    CHAR FuncBuf[MAX_PATH] = { 0 };
    if (HttpGet(url.c_str(), TempBuf, sizeof(TempBuf)) == 0) {
        return result;
    }

    if (memcmp(TempBuf, "AAAAA", 5) == NULL) {
        return result;
    }
    else {
        base64_decode((const char*)TempBuf, sizeof(TempBuf), (unsigned char*)FuncBuf);
        result = *(PULONG)FuncBuf;
    }

    return (UINT32)result;
}

UINT32 GetServceStructField(const char* Guid, const char* Name, const char* StructName, const char* FieldName)
{
    UINT32 result = 0;

    auto url = std::string("http://") + std::string(SERVICE_IP) + std::string(":") + std::string(SERVICE_PORT) + std::string("/GetSymbols/") +
        std::string(Name) + std::string("/") + std::string(Guid) + std::string("/struct/") + StructName + std::string("/") + FieldName + std::string("/")
        + std::string("null");

    CHAR TempBuf[MAX_PATH] = { 0 };
    CHAR FuncBuf[MAX_PATH] = { 0 };
    if (HttpGet(url.c_str(), TempBuf, sizeof(TempBuf)) == 0) {
        return result;
    }

    if (memcmp(TempBuf, "AAAAA", 5) == NULL) {
        return result;
    }
    else {
        base64_decode((const char*)TempBuf, sizeof(TempBuf), (unsigned char*)FuncBuf);
        result = *(PULONG)FuncBuf;
    }

    return (UINT32)result;
}

unsigned int GetFuncAddress(const char* Path, const char* FuncName)
{
    std::string Guid;
    std::string Name;


    if (!GetDBGGuid(Path, Guid, Name))
    {
        return 0;
    }

    return GetServceFuncAddress(Guid.c_str(), Name.c_str(), FuncName);
}

unsigned int GetStructField(const char* Path, const char* StructName, const char* FieldName)
{
    std::string Guid;
    std::string Name;


    if (!GetDBGGuid(Path, Guid, Name))
    {
        return 0;
    }

    return  GetServceStructField(Guid.c_str(), Name.c_str(), StructName, FieldName);
}
