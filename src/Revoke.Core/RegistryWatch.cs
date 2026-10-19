using Microsoft.Win32;

namespace Revoke.Core;

/// <summary>
/// Says whether a registry key, and with <c>subtree</c> everything under it, changed since
/// the last time it was asked, so what's read from it is read again only then. Windows
/// sets an event on the change (RegNotifyChangeKeyValue), which costs nothing while
/// nothing changes. Where the key can't be watched, it always says it changed.
/// </summary>
public sealed class RegistryWatch : IDisposable
{
    readonly RegistryKey? key;
    readonly bool subtree;
    readonly AutoResetEvent changed = new(false);
    bool watching;

    public RegistryWatch(RegistryKey root, string path, bool subtree)
    {
        this.subtree = subtree;
        try { key = root.OpenSubKey(path); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException) { }
    }

    /// <summary>Whether the key changed since the last call. True the first time, and whenever
    /// Windows wouldn't watch it.</summary>
    public bool Changed()
    {
        if (key is null) return true;
        if (watching && !changed.WaitOne(0)) return false;
        // Watching again before the caller reads, so a change made while it reads shows next time.
        watching = Native.RegNotifyChangeKeyValue(key.Handle, subtree,
            Native.REG_NOTIFY_CHANGE_NAME | Native.REG_NOTIFY_CHANGE_LAST_SET | Native.REG_NOTIFY_THREAD_AGNOSTIC,
            changed.SafeWaitHandle, asynchronous: true) == 0;
        return true;
    }

    public void Dispose()
    {
        key?.Dispose();
        changed.Dispose();
    }
}
