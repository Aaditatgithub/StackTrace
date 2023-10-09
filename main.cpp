#include <Windows.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <iostream>
#include <Psapi.h>
#pragma comment(lib, "Dbghelp.lib")

void PrintStackTrace(HANDLE hProcess)
{
    // Initialize the symbol handler.
    SymInitialize(hProcess, nullptr, TRUE);

    // Create a SYMBOL_INFO structure for the stack trace.
    IMAGEHLP_SYMBOL64* symbol = (IMAGEHLP_SYMBOL64*)malloc(sizeof(IMAGEHLP_SYMBOL64) + 256 * sizeof(char));
    symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
    symbol->MaxNameLength = 255;

    // Get the thread list.
    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    Thread32First(hThreadSnap, &te);

    do
    {
        if (te.th32OwnerProcessID == GetProcessId(hProcess))
        {
            // Open the thread to get its context.
            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (hThread)
            {
                CONTEXT context;
                context.ContextFlags = CONTEXT_FULL;
                SuspendThread(hThread);
                if (GetThreadContext(hThread, &context))
                {
                    // Read the stack.
                    DWORD machineType;
                    STACKFRAME64 stackFrame;
                    ZeroMemory(&stackFrame, sizeof(STACKFRAME64));

#if defined(_M_IX86)
                    machineType = IMAGE_FILE_MACHINE_I386;
                    stackFrame.AddrPC.Offset = context.Eip;
                    stackFrame.AddrFrame.Offset = context.Ebp;
                    stackFrame.AddrStack.Offset = context.Esp;
#elif defined(_M_X64)
                    machineType = IMAGE_FILE_MACHINE_AMD64;
                    stackFrame.AddrPC.Offset = context.Rip;
                    stackFrame.AddrFrame.Offset = context.Rsp;
                    stackFrame.AddrStack.Offset = context.Rsp;
#endif
                    stackFrame.AddrPC.Mode = AddrModeFlat;
                    stackFrame.AddrFrame.Mode = AddrModeFlat;
                    stackFrame.AddrStack.Mode = AddrModeFlat;

                    // Print the stack trace.
                    while (StackWalk64(machineType, hProcess, hThread, &stackFrame, &context, nullptr,
                        SymFunctionTableAccess64, SymGetModuleBase64, nullptr))
                    {
                        DWORD64 address = stackFrame.AddrPC.Offset;
                        if (address != 0)
                        {
                            // Get symbol information for the address.
                            if (SymGetSymFromAddr(hProcess, address, nullptr, symbol))
                            {
                                printf("Function: %s\n", symbol->Name);
                            }
                            else
                            {
                                printf("Function: Unknown\n");
                            }
                        }
                    }
                }
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hThreadSnap, &te));

    SymCleanup(hProcess);
    free(symbol);
    CloseHandle(hThreadSnap);
}



bool LaunchProcess(const wchar_t* targetProcessPath, wchar_t* commandLineArgs = nullptr)
{
    // Security attributes for the process (optional).
    LPSECURITY_ATTRIBUTES lpProcessAttributes = nullptr;

    // Security attributes for the thread (optional).
    LPSECURITY_ATTRIBUTES lpThreadAttributes = nullptr;

    // Set to TRUE to inherit handles from the parent process or FALSE to not inherit.
    BOOL bInheritHandles = FALSE;

    // Flags for the new process (e.g., CREATE_NEW_CONSOLE, CREATE_SUSPENDED, etc.).
    DWORD dwCreationFlags = CREATE_NEW_CONSOLE;

    // Environment variables (optional, nullptr for the current process's environment).
    LPVOID lpEnvironment = nullptr;

    // Current directory for the new process (optional, nullptr for the current process's directory).
    LPWSTR lpCurrentDirectory = nullptr;

    // Startup information for the new process.
    STARTUPINFOW startupInfo;
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);

    // Process information for the new process.
    PROCESS_INFORMATION processInfo;
    ZeroMemory(&processInfo, sizeof(processInfo));

    // Start the new process.
    if (!CreateProcessW(targetProcessPath, commandLineArgs, lpProcessAttributes, lpThreadAttributes, bInheritHandles,
        dwCreationFlags, lpEnvironment, lpCurrentDirectory, &startupInfo, &processInfo))
    {
        std::cerr << "Failed to create the process. Error code: " << GetLastError() << std::endl;
        return false;
    }

    // Close handles to avoid resource leaks.
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);

    return true;
}

int main()
{
    // Replace "C:\\path\\to\\your\\program.exe" with the path to the target program.
    const wchar_t* targetProcessPath = L"C:\\ConsoleApplication1\\x64\\Debug\\ConsoleApplication1.exe";

    // Additional command-line arguments if needed.
    wchar_t* commandLineArgs = nullptr;

    /*
    // Launch the process using the function.
    if (LaunchProcess(targetProcessPath, commandLineArgs))
    {
        std::cout << "Process launched successfully." << std::endl;
    }
    else
    {
        std::cerr << "Failed to launch the process." << std::endl;
    }
    
    */

    // Get the list of all running processes.
    DWORD processes[1024];
    DWORD needed;
    if (!EnumProcesses(processes, sizeof(processes), &needed))
    {
        std::cerr << "Failed to enumerate processes." << std::endl;
        return 1;
    }

    // Calculate the number of processes returned.
    DWORD numProcesses = needed / sizeof(DWORD);

    Sleep(900);
    // Iterate through the list of processes.
    for (DWORD i = 0; i < numProcesses; i++)
    {
        // Open each process with the necessary permissions.
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processes[i]);
        if (hProcess != nullptr)
        {
            TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

            // Get the process name.
            HMODULE hMod;
            DWORD cbNeeded;
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)){
                GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
            }

            // Print the process name and ID.
            //std::wcout << L"Process Name: " << szProcessName << L", Process ID: " << processes[i] << std::endl;
            do {

            // Check if the process is "notepad.exe" and print its stack trace.
            if (_wcsicmp(szProcessName, L"ConsoleApplication1.exe") == 0)
            {
                std::cout << "Stack Trace for ConsoleApplication : ";
                PrintStackTrace(hProcess);
            }
            } while (hProcess);

            CloseHandle(hProcess);
        }
    }
    return 0;
}