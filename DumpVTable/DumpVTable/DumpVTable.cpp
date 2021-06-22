#include "stdafx.h"

// TODO: Should not throw exceptions from destructors

#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>


// C/C++ standard headers
// Other external headers
// Windows headers
// Original headers


////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//


////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//


////////////////////////////////////////////////////////////////////////////////
//
// types
//

// Represents a set of a symbol name and its address.
// Used to create an output Python file.
struct Symbol
{
    uintptr_t address;
    std::wstring name;
};


// Scoped OLE Initialize.
struct ScopedOleInitialize
{
    ScopedOleInitialize();
    ~ScopedOleInitialize();
};


// Scoped DllRegisterServer.
class ScopedDllRegisterServer
{
public:
    ScopedDllRegisterServer(
        const std::wstring& FilePath);

    ~ScopedDllRegisterServer();

private:
    using DllRegisterServerType = HRESULT(__stdcall*)();

    std::unique_ptr<
        std::remove_pointer<HMODULE>::type, decltype(&::FreeLibrary)> module;
    DllRegisterServerType dllUnregisterServerPtr;
};


////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

bool AppMain(
    const std::vector<std::wstring>& Args);

bool IsOkayToExecuteTargetFile();

intptr_t GetGapByASLR(
    const std::wstring& FilePath);

std::vector<CLSID> GetClassIDsFromFile(
    const std::wstring& FilePath);

bool GetComponentObjectClassId(
    ITypeInfo* IFTypeInfo,
    std::vector<CLSID>& ClassIDs);

bool GetSymbolNames(
    const CLSID& ClassId,
    std::vector<Symbol>& Symbols,
    const std::wstring& TargetFilePath);

HMODULE GetAssociatedModule(
    uintptr_t Address);

bool HasTypeInfo(
    IDispatch* Dispatch);

std::wstring GetInterfaceName(
    ITypeInfo* TypeInfo);

Symbol GetSymbolForDescription(
    ITypeInfo* TypeInfo,
    const FUNCDESC* FuncDesc,
    const Symbol& VTable);

std::wstring GetMethodOrPropertyName(
    ITypeInfo* TypeInfo,
    const FUNCDESC* FuncDesc);

bool GenerateOutput(
    const std::wstring& OutFilePath,
    const std::vector<Symbol>& Symbols,
    intptr_t Gap);

std::string FormatString(
    const char* Format,
    ...);

std::string GetErrorMessage(
    uint32_t ErrorCode);

std::wstring GetModuleName(
    HMODULE ModuleHandle);

std::wstring GUIDToString(
    const GUID& GloballyUniqueId);


////////////////////////////////////////////////////////////////////////////////
//
// variables
//


////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

int wmain(int argc, wchar_t* argv[])
{
    int result = EXIT_FAILURE;
    try
    {
        std::vector<std::wstring> args;
        for (int i = 0; i < argc; ++i)
        {
            args.push_back(argv[i]);
        }
        if (AppMain(args))
        {
            result = EXIT_SUCCESS;
        }
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }
    catch (...)
    {
        std::cout << "FATAL: An unknown exception was thrown." << std::endl;
    }
    return result;
}


bool AppMain(
    const std::vector<std::wstring>& Args)
{
    if (Args.size() < 3)
    {
        std::cout
            << "usage:\n"
            << "    >this.exe target_file out_file [-r] [-y]\n"
            << "\n"
            << "    target_file: A path of a target COM file.\n"
            << "    out_file: A file name of an output Python script.\n"
            << "    -r: Register a target file as COM during analysis.\n"
            << "        It may require Administrators privilege.\n"
            << "    -y: Do not show a warning message.\n"
            << std::endl;
        return false;
    }

    // Parse command line parameters
    const auto targetFilePath = Args.at(1);
    const auto outFilePath = Args.at(2);
    bool isRegisterRequested = false;
    bool isNoWarningRequested = false;
    for (const auto& arg : Args)
    {
        if (arg == L"-r") { isRegisterRequested = true; }
        if (arg == L"-y") { isNoWarningRequested = true; }
    }

    // quit if user do not want to execute code of the target file.
    if (!isNoWarningRequested && !IsOkayToExecuteTargetFile())
    {
        return false;
    }

    ScopedOleInitialize ole;

    // Get a full path of the given file.
    auto targetFileHandle = make_unique_ptr(
        ::LoadLibraryW(targetFilePath.c_str()), ::FreeLibrary);
    const auto targetFileFullPath = GetModuleName(targetFileHandle.get());

    std::cout << FormatString(
        "INFO : [INFO ] Target = %S", targetFileFullPath.c_str())
        << std::endl;

    // Register the target file if it is requested
    std::unique_ptr<ScopedDllRegisterServer> scopedRegister;
    if (isRegisterRequested)
    {
        scopedRegister =
            std::make_unique<ScopedDllRegisterServer>(targetFileFullPath);
    }

    const auto gapByASLR = GetGapByASLR(targetFileFullPath);

    // Obtain interesting CLSIDs in the given file.
    std::vector<Symbol> symbols;
    for (const auto& clsid : GetClassIDsFromFile(targetFileFullPath))
    {
        try
        {
            // Obtain a name and its address of the public methods
            GetSymbolNames(clsid, symbols, targetFileFullPath);
        }
        catch (std::exception&)
        {
            // C++ exception is most likely a bug of this program,
            // so this program re-thorw it and stops.
            throw;
        }
        catch (...)
        {
            // Some files raise SEH exception. This program is not
            // responsible for it, so this program continues the process.
            std::cout << FormatString(
                "ERROR: An unknown exception was thrown.")
                << std::endl;
        }
    }

    // Create output from obtained information.
    GenerateOutput(outFilePath, symbols, gapByASLR);
    return true;
}


// Ask if it is okay to execute code in the given file
// Return true when user replied yes.
bool IsOkayToExecuteTargetFile()
{
    std::cout
        << "** WARNING **\n"
        << "Code of the target file will be executed on your system.\n"
        << "Be careful with malicious files.\n"
        << std::endl;

    for (;;)
    {
        std::cout << "Do you want to continue? (y/n): ";
        std::string input;
        std::cin >> input;
        if (input == "y" || input == "Y")
        {
            return true;
        }
        if (input == "n" || input == "N")
        {
            return false;
        }
    }
}


// Return the difference between ImageBase in the file and ImageBase
// in the current process image. This value is necessary to ignore effect
// of ASLR to create a Python script.
// Throw std::runtime_error when the value cannot be obtained.
intptr_t GetGapByASLR(
    const std::wstring& FilePath)
{
    // Load the module and get its IMAGE_NT_HEADER.
    const auto module = make_unique_ptr(
        ::LoadLibrary(FilePath.c_str()), ::FreeLibrary);
    if (!module)
    {
        const auto errorCode = ::GetLastError();
        const auto msg = FormatString(
            "FATAL: LoadLibrary failed %08X [%s]",
            errorCode, GetErrorMessage(errorCode).c_str());
        throw std::runtime_error(msg);
    }

    const auto header = ::ImageNtHeader(module.get());
    if (!header)
    {
        const auto errorCode = ::GetLastError();
        const auto msg = FormatString(
            "FATAL: ImageNtHeader failed %08X [%s]",
            errorCode, GetErrorMessage(errorCode).c_str());
        throw std::runtime_error(msg);
    }

    // Get distance between the head of the file
    // and an address of ImageBase field.
    const auto offset =
        reinterpret_cast<uintptr_t>(&header->OptionalHeader.ImageBase) -
        reinterpret_cast<uintptr_t>(module.get());

    // Read ImageBase field from the file.
    auto file = std::ifstream{ FilePath, std::ios::binary };
    if (!file)
    {
        const auto msg = FormatString("FATAL: std::ifstream failed.");
        throw std::runtime_error(msg);
    }
    if (!file.seekg(offset).good())
    {
        const auto msg = FormatString("FATAL: seekg failed.");
        throw std::runtime_error(msg);
    }
    uintptr_t imageBaseOnFile = 0;
    if (!file.read(reinterpret_cast<char*>(&imageBaseOnFile),
        sizeof(imageBaseOnFile)).good())
    {
        const auto msg = FormatString("FATAL: read failed.");
        throw std::runtime_error(msg);
    }

    // Return the gap between them.
    return imageBaseOnFile - header->OptionalHeader.ImageBase;
}


// Collect all CLSIDs representing a Component Object in the given file.
std::vector<CLSID> GetClassIDsFromFile(
    const std::wstring& FilePath)
{
    std::vector<CLSID> ClassIDs;

    // Get a type library.
    ITypeLib* typelib = nullptr;
    auto result = ::LoadTypeLibEx(FilePath.c_str(), REGKIND_NONE, &typelib);
    if (!SUCCEEDED(result))
    {
        const auto msg = FormatString(
            "ERROR: LoadTypeLibEx returned %08X [%s]",
            result, GetErrorMessage(result).c_str());
        std::cout << msg << std::endl;
        return ClassIDs;
    }

    // Enumerate all types in the type library.
    const UINT numberOfTypeInfo = typelib->GetTypeInfoCount();
    if (numberOfTypeInfo == 0)
    {
        const auto msg = FormatString(
            "ERROR: ITypeLib::GetTypeInfoCount returned 0");
        std::cout << msg << std::endl;
        return ClassIDs;
    }

    for (UINT i = 0; i < numberOfTypeInfo; ++i)
    {
        ITypeInfo* ifTypeInfo = nullptr;
        result = typelib->GetTypeInfo(i, &ifTypeInfo);
        if (!SUCCEEDED(result))
        {
            const auto msg = FormatString(
                "ERROR: ITypeLib::GetTypeInfo returned %08X [%s]",
                result, GetErrorMessage(result).c_str());
            std::cout << msg << std::endl;
            continue;
        }

        // Check and add this type when it is necessary.
        GetComponentObjectClassId(ifTypeInfo, ClassIDs);
    }
    return ClassIDs;
}


// Add CLSID in ClassIDs when it is a Component Object (TKIND_COCLASS).
// returns true when CLSID is added.
bool GetComponentObjectClassId(
    ITypeInfo* IFTypeInfo,
    std::vector<CLSID>& ClassIDs)
{
    TYPEATTR* ifTypeAttribute = nullptr;
    auto result = IFTypeInfo->GetTypeAttr(&ifTypeAttribute);
    if (!SUCCEEDED(result))
    {
        const auto msg = FormatString(
            "ERROR: ITypeInfo::GetTypeAttr returned %08X [%s]",
            result, GetErrorMessage(result).c_str());
        std::cout << msg << std::endl;
        return false;
    }
    auto ifTypeAttributeScope = make_unique_ptr(ifTypeAttribute,
        [IFTypeInfo](TYPEATTR* p) { IFTypeInfo->ReleaseTypeAttr(p); });

    // Just log
    const auto interfaceName = GetInterfaceName(IFTypeInfo);
    std::cout << FormatString(
        "INFO : [CLSID] %-20S %d %S",
        GUIDToString(ifTypeAttribute->guid).c_str(),
        ifTypeAttribute->typekind, interfaceName.c_str())
        << std::endl;

    if (ifTypeAttribute->typekind != TKIND_COCLASS)
    {
        return false;
    }

    // Add CLSID.
    ClassIDs.push_back(ifTypeAttribute->guid);
    return true;
}


// Add symbols included in ClassId into Symbols.
// The symbol is either a vtable address or a function address with its name.
bool GetSymbolNames(
    const CLSID& ClassId,
    std::vector<Symbol>& Symbols,
    const std::wstring& TargetFilePath)
{
    // Query IUnknown interface
    IUnknown* unknown = nullptr;
    auto result = ::CoCreateInstance(ClassId, nullptr,
        CLSCTX_INPROC_HANDLER | CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
        IID_IUnknown, reinterpret_cast<void**>(&unknown));
    if (!SUCCEEDED(result))
    {
        const auto msg = FormatString(
            "ERROR: %S CoCreateInstance returned %08X [%s]",
            GUIDToString(ClassId).c_str(),
            result, GetErrorMessage(result).c_str());
        std::cout << msg << std::endl;
        return false;
    }
    auto unknownScope = make_unique_ptr(unknown,
        [](IUnknown* p) { p->Release(); });


    // Query IDispatch interface
    IDispatch* dispatch = nullptr;
    result = unknown->QueryInterface(IID_IDispatch,
        reinterpret_cast<void**>(&dispatch));
    if (!SUCCEEDED(result))
    {
        const auto msg = FormatString(
            "ERROR: %S IUnknown::QueryInterface returned %08X [%s]",
            GUIDToString(ClassId).c_str(),
            result, GetErrorMessage(result).c_str());
        std::cout << msg << std::endl;
        return false;
    }
    auto dispatchScope = make_unique_ptr(dispatch,
        [](IDispatch* p) { p->Release(); });


    if (!HasTypeInfo(dispatch))
    {
        const auto msg = FormatString(
            "ERROR: %S IDispatch does not have type information.",
            GUIDToString(ClassId).c_str());
        std::cout << msg << std::endl;
        return false;
    }

    ITypeInfo* typeInfo = nullptr;
    result = dispatch->GetTypeInfo(0, ::GetUserDefaultLCID(), &typeInfo);
    if (!SUCCEEDED(result))
    {
        const auto msg = FormatString(
            "ERROR: %S IDispatch::GetTypeInfoCount returned %08X [%s]",
            GUIDToString(ClassId).c_str(),
            result, GetErrorMessage(result).c_str());
        std::cout << msg << std::endl;
        return false;
    }

    // Get a name of the interface and an address of its vtable.
    const auto interfaceName = GetInterfaceName(typeInfo);
    const auto addressOfVTable = *reinterpret_cast<uintptr_t*>(dispatch);

    // Make sure if an associated file is the target file.
    const auto moduleBase = GetAssociatedModule(addressOfVTable);
    const auto modulePath = GetModuleName(moduleBase);
    if (TargetFilePath != modulePath)
    {
        const auto msg = FormatString(
            "ERROR: %S File mismatch [%S]",
            GUIDToString(ClassId).c_str(),
            modulePath.c_str());
        std::cout << msg << std::endl;
        return false;
    }

    const auto vtable = Symbol{ addressOfVTable, interfaceName };
    Symbols.push_back(vtable);

    std::cout << FormatString(
        "INFO : [VTABLE] %p %S", addressOfVTable, interfaceName.c_str())
        << std::endl;

    // Enumerate all entries of the interface (methods and properties).
    TYPEATTR* typeAttribute = nullptr;
    result = typeInfo->GetTypeAttr(&typeAttribute);
    if (!SUCCEEDED(result))
    {
        const auto msg = FormatString(
            "ERROR: %S ITypeInfo::GetTypeAttr returned %08X [%s]",
            GUIDToString(ClassId).c_str(),
            result, GetErrorMessage(result).c_str());
        std::cout << msg << std::endl;
        return false;
    }
    auto libAttributeScope = make_unique_ptr(typeAttribute,
        [typeInfo](TYPEATTR* p) { typeInfo->ReleaseTypeAttr(p); });

    for (UINT i = 0; i < typeAttribute->cFuncs; ++i)
    {
        // Get a description of the entry.
        FUNCDESC* funcDesc = nullptr;
        result = typeInfo->GetFuncDesc(i, &funcDesc);
        if (!SUCCEEDED(result))
        {
            const auto msg = FormatString(
                "ERROR: %S ITypeInfo::GetFuncDesc returned %08X [%s]",
                GUIDToString(ClassId).c_str(),
                result, GetErrorMessage(result).c_str());
            std::cout << msg << std::endl;
            continue;
        }
        auto libAttributeScope = make_unique_ptr(funcDesc,
            [typeInfo](FUNCDESC* p) { typeInfo->ReleaseFuncDesc(p); });

        // In some classes, oVft have always 0. This code fills oVft with
        // a dummy offset.
        // TODO: fix it.
        if (funcDesc->oVft == 0 && i != 0)
        {
            funcDesc->oVft = static_cast<SHORT>(i * 4);
            const auto msg = FormatString(
                "WARN : %S VTable index has been modified to %d.",
                GUIDToString(ClassId).c_str(), i);
            std::cout << msg << std::endl;
        }

        // Get interesting information from the description.
        Symbols.push_back(GetSymbolForDescription(typeInfo, funcDesc, vtable));
    }
    return true;
}


// Return the module handle of the file contains the address.
HMODULE GetAssociatedModule(
    uintptr_t Address)
{
    auto snapshotHandle = make_unique_ptr(
        ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ::GetCurrentProcessId()),
        ::CloseHandle);
    if (snapshotHandle.get() == INVALID_HANDLE_VALUE)
    {
        return nullptr;
    }

    MODULEENTRY32 moe = { sizeof(moe) };
    for (auto b = ::Module32First(snapshotHandle.get(), &moe);
        b;
        b = ::Module32Next(snapshotHandle.get(), &moe))
    {
        const auto moduleBase = moe.modBaseAddr;
        const auto moduleEnd = moe.modBaseAddr + moe.modBaseSize;

        if (is_in_range(reinterpret_cast<BYTE*>(Address), moduleBase, moduleEnd))
        {
            return moe.hModule;
        }
    }
    return nullptr;
}


// Return true when the given interface has the type library.
bool HasTypeInfo(
    IDispatch* Dispatch)
{
    UINT typeInfoCount = 0;
    auto result = Dispatch->GetTypeInfoCount(&typeInfoCount);
    return SUCCEEDED(result) && (typeInfoCount == 1);
}


// Return a interface name.
std::wstring GetInterfaceName(
    ITypeInfo* TypeInfo)
{
    BSTR interfaceName = nullptr;
    auto result = TypeInfo->GetDocumentation(MEMBERID_NIL, &interfaceName,
        nullptr, nullptr, nullptr);
    if (!SUCCEEDED(result))
    {
        const auto msg = FormatString(
            "ERROR: ITypeInfo::GetDocumentation returned %08X [%s]",
            result, GetErrorMessage(result).c_str());
        std::cout << msg << std::endl;
        return L"";
    }
    auto interfaceNameScope = make_unique_ptr(interfaceName,
        [](BSTR p) { ::SysFreeString(p); });
    return interfaceName;
}


// Return address and name of the given description.
Symbol GetSymbolForDescription(
    ITypeInfo* TypeInfo,
    const FUNCDESC* FuncDesc,
    const Symbol& VTable)
{
    const auto name = GetMethodOrPropertyName(TypeInfo, FuncDesc);
    const auto addressInVTable = FuncDesc->oVft + VTable.address;
    const auto address = *reinterpret_cast<uintptr_t*>(addressInVTable);
    const auto prefix =
        (FuncDesc->invkind == INVOKE_PROPERTYGET) ? L"get_" :
        (FuncDesc->invkind == INVOKE_PROPERTYPUT) ? L"put_" :
        (FuncDesc->invkind == INVOKE_PROPERTYPUTREF) ? L"ref_" : L"";
    const auto finalName = VTable.name + L"__" + prefix + name;

    std::cout << FormatString(
        "INFO : [METHOD] %3d %p %S",
        FuncDesc->oVft / 4, address, finalName.c_str())
        << std::endl;
    return{ address, finalName };
}


// Return raw name of the given description.
std::wstring GetMethodOrPropertyName(
    ITypeInfo* TypeInfo,
    const FUNCDESC* FuncDesc)
{
    UINT numberOfNames = 0;
    std::vector<BSTR> names(FuncDesc->cParams + 1);
    auto result = TypeInfo->GetNames(FuncDesc->memid,
        names.data(), names.size(), &numberOfNames);
    if (!SUCCEEDED(result))
    {
        const auto msg = FormatString(
            "ERROR: ITypeInfo::GetFuncDesc returned %08X [%s]",
            result, GetErrorMessage(result).c_str());
        std::cout << msg << std::endl;
        return L"";
    }
    auto libAttributeScope = make_unique_ptr(&names,
        [](std::vector<BSTR>* p)
    {
        for (auto name : *p) { ::SysFreeString(name); }
    });
    return names[0];
}


// Create an output file.
// Return true when an effective file is created.
// Throw std::runtime_error when the output file cannot be created.
bool GenerateOutput(
    const std::wstring& OutFilePath,
    const std::vector<Symbol>& Symbols,
    intptr_t Gap)
{
    if (Symbols.empty())
    {
        const auto msg = FormatString(
            "INFO : Information was not obtained form the given file.");
        std::cout << msg << std::endl;
        return false;
    }

    FILE* file = nullptr;
    if (_wfopen_s(&file, OutFilePath.c_str(), L"w"))
    {
        const auto msg = FormatString("FATAL: _wfopen_s failed.");
        throw std::runtime_error(msg);
    }
    auto scopedFile = make_unique_ptr(file, fclose);

    const char SCRIPT[] = "\
def make_name_n(address, name):\n\
    result = idc.set_name(address, name, SN_CHECK | SN_NOWARN)\n\
    if result:\n\
        return name\n\
\n\
    for i in range(100):\n\
        name_n = '{0}_{1}'.format(name, i)\n\
        result = idc.set_name(address, name_n, SN_CHECK | SN_NOWARN)\n\
        if result:\n\
            return name_n\n\
\n\
\n\
def main():\n\
    for entry in DUMPED_DATA:\n\
        address = entry[0]\n\
        name = entry[1]\n\
        oldname = idc.get_name(address)\n\
        newname = make_name_n(address, name)\n\
        print('%08x %-40s => %s' % (address, oldname, newname))\n\
\n\
\n\
if __name__ == '__main__':\n\
    main()\n\
";


    fprintf(file, "DUMPED_DATA = [\n");
    for (const auto& symbol : Symbols)
    {
        fprintf(file, "    [0x%p, '%S'],\n",
            symbol.address + Gap, symbol.name.c_str());
    }
    fprintf(file, "]\n\n");
    fprintf(file, "%s", SCRIPT);
    return true;
}


// Return a formatted string with a given printf format.
std::string FormatString(
    const char* Format,
    ...)
{
    char buf[2048];
    va_list varg;
    va_start(varg, Format);
    if (!SUCCEEDED(::StringCchVPrintfA(buf, _countof(buf), Format, varg)))
    {
        va_end(varg);
        return "ERROR: StringCchVPrintfA failed.";
    }
    va_end(varg);
    return buf;
}


// Return win32 error message.
std::string GetErrorMessage(
    uint32_t ErrorCode)
{
    char* message = nullptr;
    if (!::FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        nullptr, ErrorCode, LANG_USER_DEFAULT,
        reinterpret_cast<LPSTR>(&message), 0, nullptr))
    {
        return "";
    }
    auto scoped = make_unique_ptr(message, &::LocalFree);

    const auto length = ::strlen(message);
    if (!length)
    {
        return "";
    }

    if (message[length - 2] == '\r')
    {
        message[length - 2] = '\0';
    }
    return message;
}


// Return normalized full path of the file.
std::wstring GetModuleName(
    HMODULE ModuleHandle)
{
    wchar_t modulePathS[1024];
    ::GetModuleFileNameW(ModuleHandle, modulePathS, _countof(modulePathS));
    wchar_t modulePath[1024];
    ::GetLongPathNameW(modulePathS, modulePath, _countof(modulePath));
    return modulePath;
}


// Convert GUID to a string.
std::wstring GUIDToString(
    const GUID& GloballyUniqueId)
{
    wchar_t str[40] = {};
    if (!::StringFromGUID2(GloballyUniqueId, str, _countof(str)))
    {
        const auto errorCode = ::GetLastError();
        const auto msg = FormatString(
            "FATAL: StringFromGUID2 failed %08X [%s]",
            errorCode, GetErrorMessage(errorCode).c_str());
        throw std::runtime_error(msg);
    }
    return str;
}


//
// ScopedOleInitialize
//

// Initialize OLE.
// Throw std::runtime_error when the initialization failed.
ScopedOleInitialize::ScopedOleInitialize()
{
    auto result = ::OleInitialize(nullptr);
    if (!SUCCEEDED(result))
    {
        const auto msg = FormatString(
            "FATAL: OleInitialize returned %08X [%s]",
            result, GetErrorMessage(result).c_str());
        throw std::runtime_error(msg);
    }
}


ScopedOleInitialize::~ScopedOleInitialize()
{
    ::OleUninitialize();
}


//
// ScopedDllRegisterServer
//

// Execute DllRegisterServer function in the target file to register it.
// Throw std::runtime_error when the registration failed or the unregister
// function cannot be found.
ScopedDllRegisterServer::ScopedDllRegisterServer(
    const std::wstring& FilePath)
    : module(make_unique_ptr(::LoadLibrary(FilePath.c_str()), ::FreeLibrary))
    , dllUnregisterServerPtr(nullptr)
{
    // Load the target file.
    if (!module)
    {
        const auto errorCode = ::GetLastError();
        const auto msg = FormatString(
            "FATAL: LoadLibrary failed %08X [%s]",
            errorCode, GetErrorMessage(errorCode).c_str());
        throw std::runtime_error(msg);
    }

    // Obtain register and unregister routines.
    const auto dllRegisterServerPtr = reinterpret_cast<DllRegisterServerType>(
        ::GetProcAddress(module.get(), "DllRegisterServer"));
    dllUnregisterServerPtr = reinterpret_cast<DllRegisterServerType>(
        ::GetProcAddress(module.get(), "DllUnregisterServer"));
    if (!dllRegisterServerPtr || !dllUnregisterServerPtr)
    {
        const auto errorCode = ::GetLastError();
        const auto msg = FormatString(
            "FATAL: DllRegisterServer or/and DllUnregisterServer not found %08X [%s]",
            errorCode, GetErrorMessage(errorCode).c_str());
        throw std::runtime_error(msg);
    }

    // Execute the register routine.
    auto result = dllRegisterServerPtr();
    if (!SUCCEEDED(result))
    {
        const auto msg = FormatString(
            "FATAL: DllRegisterServer returned %08X [%s]",
            result, GetErrorMessage(result).c_str());
        throw std::runtime_error(msg);
    }
}


// Execute DllUnregisterServer to unregister it.
ScopedDllRegisterServer::~ScopedDllRegisterServer()
{
    auto result = dllUnregisterServerPtr();
    if (!SUCCEEDED(result))
    {
        const auto msg = FormatString(
            "ERROR: DllUnregisterServerPtr returned %08X [%s]",
            result, GetErrorMessage(result).c_str());
        std::cout << msg << std::endl;
    }
}

