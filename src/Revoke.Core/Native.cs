using System.Runtime.InteropServices;

namespace Revoke.Core;

/// <summary>The Win32 calls .NET doesn't wrap: process trees, package identity, windows, and
/// quick looks at services and the registry.</summary>
internal static unsafe partial class Native
{
    public const uint PROCESS_TERMINATE = 0x1;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint GW_OWNER = 4;
    public const int GWL_EXSTYLE = -20;
    public const int WS_EX_TOOLWINDOW = 0x80;
    public const uint DWMWA_CLOAKED = 14;

    public const int SystemProcessInformation = 5;
    public const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public char* Buffer;
    }

    /// <summary>
    /// The start of each entry NtQuerySystemInformation returns for SystemProcessInformation.
    /// winternl.h keeps the creation time and the parent's ID in fields it calls reserved;
    /// this is the full layout, unchanged since Windows NT, which Toolhelp32 reads too.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_PROCESS_INFORMATION
    {
        public uint NextEntryOffset;
        public uint NumberOfThreads;
        public long WorkingSetPrivateSize;
        public uint HardFaultCount;
        public uint NumberOfThreadsHighWatermark;
        public ulong CycleTime;
        public long CreateTime;
        public long UserTime;
        public long KernelTime;
        public UNICODE_STRING ImageName;
        public int BasePriority;
        public nint UniqueProcessId;
        public nint InheritedFromUniqueProcessId;
    }

    [LibraryImport("ntdll.dll")]
    public static partial int NtQuerySystemInformation(int infoClass, void* buffer, uint length, out uint returnLength);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CloseHandle(nint handle);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool QueryFullProcessImageNameW(nint process, uint flags, char* name, ref uint size);

    [LibraryImport("kernel32.dll")]
    public static partial int GetPackageFamilyName(nint process, ref uint length, char* name);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetProcessTimes(nint process, out long creation, out long exit, out long kernel, out long user);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool TerminateProcess(nint process, uint exitCode);

    public const uint STILL_ACTIVE = 259;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetExitCodeProcess(nint process, out uint exitCode);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool EnumWindows(delegate* unmanaged<nint, nint, int> callback, nint lParam);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool IsWindowVisible(nint hwnd);

    [LibraryImport("user32.dll")]
    public static partial nint GetWindow(nint hwnd, uint command);

    [LibraryImport("user32.dll")]
    public static partial int GetWindowLongW(nint hwnd, int index);

    [LibraryImport("user32.dll")]
    public static partial int GetWindowTextLengthW(nint hwnd);

    [LibraryImport("user32.dll")]
    public static partial uint GetWindowThreadProcessId(nint hwnd, out uint processId);

    public const uint MB_OK = 0x0;
    public const uint MB_YESNO = 0x4;
    public const uint MB_ICONERROR = 0x10;
    public const uint MB_ICONWARNING = 0x30;
    public const uint MB_DEFBUTTON2 = 0x100;
    public const uint MB_SETFOREGROUND = 0x10000;
    public const uint MB_TOPMOST = 0x40000;
    public const int IDYES = 6;

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    public static partial int MessageBoxW(nint owner, string text, string caption, uint type);

    [LibraryImport("dwmapi.dll")]
    public static partial int DwmGetWindowAttribute(nint hwnd, uint attribute, out uint value, uint size);

    public const uint SC_MANAGER_CONNECT = 0x1;
    public const uint SERVICE_QUERY_STATUS = 0x4;
    public const uint SERVICE_STOPPED = 1;

    [StructLayout(LayoutKind.Sequential)]
    public struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    public static partial nint OpenSCManagerW(string? machine, string? database, uint access);

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    public static partial nint OpenServiceW(nint manager, string name, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool QueryServiceStatus(nint service, out SERVICE_STATUS status);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CloseServiceHandle(nint handle);

    public const uint REG_NOTIFY_CHANGE_NAME = 0x1;
    public const uint REG_NOTIFY_CHANGE_LAST_SET = 0x4;
    public const uint REG_NOTIFY_THREAD_AGNOSTIC = 0x10000000;

    [LibraryImport("advapi32.dll")]
    public static partial int RegNotifyChangeKeyValue(Microsoft.Win32.SafeHandles.SafeRegistryHandle key,
        [MarshalAs(UnmanagedType.Bool)] bool watchSubtree, uint filter, Microsoft.Win32.SafeHandles.SafeWaitHandle @event,
        [MarshalAs(UnmanagedType.Bool)] bool asynchronous);
}
