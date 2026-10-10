using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Revoke;

/// <summary>
/// The notification-area icon, on a hidden window of its own. The same window hears
/// about the session locking, the PC going to sleep, the theme changing, and Explorer
/// restarting (which takes every tray icon with it).
/// </summary>
sealed unsafe partial class TrayIcon : IDisposable
{
    public enum MenuCommand { RevokeAll = 1, Settings, Quit, EndAll }

    /// <summary>A left click or Enter on the icon, with the icon's rectangle on screen.</summary>
    public event Action<RECT>? Selected;
    public event Action<MenuCommand>? Command;
    public event Action<string>? Locked;

    const uint CallbackMessage = 0x8000 + 1; // WM_APP + 1
    const uint IconId = 1;
    static TrayIcon? current;
    readonly nint hwnd;
    readonly uint taskbarCreated;
    nint icon;
    string iconName = "";
    bool exposed;
    string tooltip = "Revoke";

    public TrayIcon()
    {
        current = this;
        var instance = GetModuleHandleW(null);
        fixed (char* className = "RevokeTray")
        {
            var windowClass = new WNDCLASSEXW
            {
                cbSize = (uint)sizeof(WNDCLASSEXW),
                lpfnWndProc = &WindowProc,
                hInstance = instance,
                lpszClassName = className,
            };
            RegisterClassExW(ref windowClass);
            // A top-level window, never shown: message-only windows don't get broadcasts
            // like WM_POWERBROADCAST and TaskbarCreated.
            hwnd = CreateWindowExW(0, className, className, 0, 0, 0, 0, 0, 0, 0, instance, 0);
        }
        taskbarCreated = RegisterWindowMessageW("TaskbarCreated");
        WTSRegisterSessionNotification(hwnd, 0); // NOTIFY_FOR_THIS_SESSION
        Add();
    }

    /// <summary>A lock in the taskbar's text color, like Windows' own icons: open while a
    /// watched app is running, closed otherwise.</summary>
    public void Update(bool exposed, string status)
    {
        this.exposed = exposed;
        // Windows cuts tray tooltips off at 127 characters.
        tooltip = $"Revoke: {status}";
        if (tooltip.Length > 127) tooltip = tooltip[..126] + "…";
        Modify();
    }

    void Add()
    {
        var data = Data();
        Shell_NotifyIconW(0, ref data); // NIM_ADD
        data.uVersion = 4; // NOTIFYICON_VERSION_4
        Shell_NotifyIconW(4, ref data); // NIM_SETVERSION
    }

    void Modify()
    {
        var data = Data();
        Shell_NotifyIconW(1, ref data); // NIM_MODIFY
    }

    NOTIFYICONDATAW Data()
    {
        var name = $"tray-{(exposed ? "open" : "closed")}-{(LightTaskbar() ? "light" : "dark")}.ico";
        if (name != iconName || icon == 0)
        {
            if (icon != 0) DestroyIcon(icon);
            var size = GetSystemMetricsForDpi(49, GetDpiForSystem()); // SM_CXSMICON
            icon = LoadImageW(0, Path.Combine(AppContext.BaseDirectory, "Assets", name), 1, size, size, 0x10); // IMAGE_ICON, LR_LOADFROMFILE
            iconName = name;
        }
        var data = new NOTIFYICONDATAW
        {
            cbSize = (uint)sizeof(NOTIFYICONDATAW),
            hWnd = hwnd,
            uID = IconId,
            uFlags = 0x1 | 0x2 | 0x4 | 0x80, // NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP
            uCallbackMessage = CallbackMessage,
            hIcon = icon,
        };
        var tip = tooltip.AsSpan();
        for (var i = 0; i < tip.Length && i < 127; i++) data.szTip[i] = tip[i];
        return data;
    }

    static bool LightTaskbar() =>
        Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")?
            .GetValue("SystemUsesLightTheme") is int light && light == 1;

    RECT IconRect()
    {
        var id = new NOTIFYICONIDENTIFIER { cbSize = (uint)sizeof(NOTIFYICONIDENTIFIER), hWnd = hwnd, uID = IconId };
        if (Shell_NotifyIconGetRect(ref id, out var rect) == 0) return rect;
        GetCursorPos(out var point);
        return new RECT { left = point.x, top = point.y, right = point.x, bottom = point.y };
    }

    void ShowMenu(int x, int y)
    {
        var menu = CreatePopupMenu();
        AppendMenuW(menu, 0, (nuint)MenuCommand.RevokeAll, "Revoke all watched");
        AppendMenuW(menu, 0, (nuint)MenuCommand.EndAll, "End all tasks");
        AppendMenuW(menu, 0, (nuint)MenuCommand.Settings, "Settings…");
        AppendMenuW(menu, 0x800, 0, null); // MF_SEPARATOR
        AppendMenuW(menu, 0, (nuint)MenuCommand.Quit, "Quit Revoke");
        // The menu only closes when clicking elsewhere if its window is in front.
        SetForegroundWindow(hwnd);
        var chosen = TrackPopupMenuEx(menu, 0x100 | 0x20, x, y, hwnd, 0); // TPM_RETURNCMD | TPM_BOTTOMALIGN
        DestroyMenu(menu);
        if (chosen != 0) Command?.Invoke((MenuCommand)chosen);
    }

    nint Handle(uint message, nuint wParam, nint lParam)
    {
        if (message == CallbackMessage)
        {
            switch ((uint)(lParam & 0xFFFF))
            {
                case 0x400: // NIN_SELECT
                case 0x401: // NIN_KEYSELECT
                    Selected?.Invoke(IconRect());
                    break;
                case 0x7B: // WM_CONTEXTMENU
                    ShowMenu((short)(wParam & 0xFFFF), (short)((wParam >> 16) & 0xFFFF));
                    break;
            }
            return 0;
        }
        if (message == taskbarCreated)
        {
            Add();
            return 0;
        }
        switch (message)
        {
            case 0x2B1 when wParam == 7: // WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK
                Locked?.Invoke("the screen locked");
                break;
            case 0x218 when wParam == 4: // WM_POWERBROADCAST, PBT_APMSUSPEND
                Locked?.Invoke("the PC went to sleep");
                break;
            case 0x1A: // WM_SETTINGCHANGE: the taskbar may have switched between light and dark.
            case 0x7E: // WM_DISPLAYCHANGE: or the icon size changed.
                iconName = "";
                Modify();
                break;
        }
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }

    [UnmanagedCallersOnly]
    static nint WindowProc(nint hwnd, uint message, nuint wParam, nint lParam) =>
        current is { } tray && tray.hwnd == hwnd ? tray.Handle(message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);

    public void Dispose()
    {
        var data = new NOTIFYICONDATAW { cbSize = (uint)sizeof(NOTIFYICONDATAW), hWnd = hwnd, uID = IconId };
        Shell_NotifyIconW(2, ref data); // NIM_DELETE
        if (icon != 0) DestroyIcon(icon);
        DestroyWindow(hwnd);
    }

    // Win32

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int left, top, right, bottom; }

    [StructLayout(LayoutKind.Sequential)]
    struct POINT { public int x, y; }

    [StructLayout(LayoutKind.Sequential)]
    struct WNDCLASSEXW
    {
        public uint cbSize, style;
        public delegate* unmanaged<nint, uint, nuint, nint, nint> lpfnWndProc;
        public int cbClsExtra, cbWndExtra;
        public nint hInstance, hIcon, hCursor, hbrBackground;
        public char* lpszMenuName, lpszClassName;
        public nint hIconSm;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct NOTIFYICONDATAW
    {
        public uint cbSize;
        public nint hWnd;
        public uint uID, uFlags, uCallbackMessage;
        public nint hIcon;
        public fixed char szTip[128];
        public uint dwState, dwStateMask;
        public fixed char szInfo[256];
        public uint uVersion;
        public fixed char szInfoTitle[64];
        public uint dwInfoFlags;
        public Guid guidItem;
        public nint hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct NOTIFYICONIDENTIFIER
    {
        public uint cbSize;
        public nint hWnd;
        public uint uID;
        public Guid guidItem;
    }

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint GetModuleHandleW(string? name);

    [LibraryImport("user32.dll")]
    private static partial ushort RegisterClassExW(ref WNDCLASSEXW windowClass);

    [LibraryImport("user32.dll")]
    private static partial nint CreateWindowExW(uint exStyle, char* className, char* windowName, uint style, int x, int y, int width, int height, nint parent, nint menu, nint instance, nint param);

    [LibraryImport("user32.dll")]
    private static partial nint DefWindowProcW(nint hwnd, uint message, nuint wParam, nint lParam);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyWindow(nint hwnd);

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint RegisterWindowMessageW(string name);

    [LibraryImport("wtsapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSRegisterSessionNotification(nint hwnd, uint flags);

    [LibraryImport("shell32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Shell_NotifyIconW(uint message, ref NOTIFYICONDATAW data);

    [LibraryImport("shell32.dll")]
    private static partial int Shell_NotifyIconGetRect(ref NOTIFYICONIDENTIFIER identifier, out RECT rect);

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint LoadImageW(nint instance, string name, uint type, int width, int height, uint flags);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyIcon(nint icon);

    [LibraryImport("user32.dll")]
    private static partial int GetSystemMetricsForDpi(int index, uint dpi);

    [LibraryImport("user32.dll")]
    private static partial uint GetDpiForSystem();

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetCursorPos(out POINT point);

    [LibraryImport("user32.dll")]
    private static partial nint CreatePopupMenu();

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AppendMenuW(nint menu, uint flags, nuint id, string? text);

    [LibraryImport("user32.dll")]
    private static partial int TrackPopupMenuEx(nint menu, uint flags, int x, int y, nint hwnd, nint parameters);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyMenu(nint menu);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetForegroundWindow(nint hwnd);
}
