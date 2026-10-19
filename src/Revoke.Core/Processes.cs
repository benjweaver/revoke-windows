using System.Runtime.InteropServices;

namespace Revoke.Core;

/// <param name="Path">Null when Windows won't say, as for protected processes.</param>
/// <param name="Family">The package family, for processes running with package identity.</param>
/// <param name="Started">Creation time as a FILETIME, which also tells a process apart from
/// a later one that reuses its ID.</param>
public sealed record Proc(uint Pid, uint Parent, string Name, string? Path, string? Family, long Started);

/// <summary>Running processes, which of them have windows, and stopping them along with
/// everything they started.</summary>
public static unsafe class Processes
{
    static readonly Lock listing = new();
    static byte[] table = new byte[512 * 1024];
    /// <summary>Each running process's program and package, by ID and creation time, which
    /// together tell it apart from a later process that reuses the ID.</summary>
    static Dictionary<(uint Pid, long Started), (string? Path, string? Family)> described = [];

    /// <summary>
    /// Every process running now. Windows lists them all in one call, with when each started
    /// and what started it. Only a process not seen before is opened, to ask for its program
    /// and package, so listing every couple of seconds costs little.
    /// </summary>
    public static List<Proc> List()
    {
        lock (listing)
        {
            var procs = new List<Proc>();
            var seen = new Dictionary<(uint, long), (string?, string?)>(described.Count);
            int status;
            while (true)
            {
                uint needed;
                fixed (byte* start = table)
                    status = Native.NtQuerySystemInformation(Native.SystemProcessInformation, start, (uint)table.Length, out needed);
                if (status != Native.STATUS_INFO_LENGTH_MISMATCH) break;
                // With room for processes that start before the next try.
                table = new byte[Math.Max((int)needed + 64 * 1024, table.Length * 2)];
            }
            if (status < 0) return procs;
            fixed (byte* start = table)
            {
                for (var entry = (Native.SYSTEM_PROCESS_INFORMATION*)start; ; entry = (Native.SYSTEM_PROCESS_INFORMATION*)((byte*)entry + entry->NextEntryOffset))
                {
                    var pid = (uint)entry->UniqueProcessId;
                    var parent = (uint)entry->InheritedFromUniqueProcessId;
                    var started = entry->CreateTime;
                    if (pid == 0)
                    {
                        procs.Add(new Proc(0, 0, "[System Process]", null, null, 0));
                    }
                    else
                    {
                        var name = new string(entry->ImageName.Buffer, 0, entry->ImageName.Length / sizeof(char));
                        if (!described.TryGetValue((pid, started), out var found)) found = Describe(pid, started);
                        seen[(pid, started)] = found;
                        procs.Add(new Proc(pid, parent, name, found.Path, found.Family, started));
                    }
                    if (entry->NextEntryOffset == 0) break;
                }
            }
            described = seen;
            return procs;
        }
    }

    /// <summary>A process's program and package. Nothing, if Windows won't say, or the
    /// process ended and its ID went to another one since it was listed.</summary>
    static (string? Path, string? Family) Describe(uint pid, long started)
    {
        var handle = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == 0) return (null, null);
        try
        {
            if (CreationTime(handle) != started) return (null, null);
            string? path = null, family = null;
            var buffer = stackalloc char[1024];
            uint size = 1024;
            if (Native.QueryFullProcessImageNameW(handle, 0, buffer, ref size)) path = new string(buffer, 0, (int)size);
            uint length = 256;
            var familyBuffer = stackalloc char[256];
            if (Native.GetPackageFamilyName(handle, ref length, familyBuffer) == 0 && length > 1)
                family = new string(familyBuffer, 0, (int)length - 1);
            return (path, family);
        }
        finally
        {
            Native.CloseHandle(handle);
        }
    }

    static long CreationTime(nint handle) =>
        Native.GetProcessTimes(handle, out var created, out _, out _, out _) ? created : 0;

    /// <summary>
    /// The processes started by <paramref name="roots"/>, their children, and so on, not
    /// counting the roots. A parent ID only counts if the parent started before the
    /// child: Windows reuses process IDs, and a child can outlive its parent.
    /// </summary>
    public static HashSet<uint> Descendants(IReadOnlyList<Proc> procs, IReadOnlySet<uint> roots)
    {
        var byPid = new Dictionary<uint, Proc>();
        foreach (var proc in procs) byPid.TryAdd(proc.Pid, proc);
        var children = new Dictionary<uint, List<Proc>>();
        foreach (var proc in procs)
        {
            if (proc.Pid != proc.Parent && byPid.TryGetValue(proc.Parent, out var parent)
                && parent.Started != 0 && proc.Started >= parent.Started)
            {
                (children.TryGetValue(proc.Parent, out var list) ? list : children[proc.Parent] = []).Add(proc);
            }
        }
        var found = new HashSet<uint>();
        var stack = new Stack<uint>(roots);
        while (stack.TryPop(out var pid))
        {
            if (!children.TryGetValue(pid, out var list)) continue;
            foreach (var child in list)
            {
                if (!roots.Contains(child.Pid) && found.Add(child.Pid)) stack.Push(child.Pid);
            }
        }
        return found;
    }

    /// <summary>Ends a process, if it's still the one that was listed. Returns why it couldn't, or null.</summary>
    public static string? Kill(Proc proc)
    {
        var handle = Native.OpenProcess(Native.PROCESS_TERMINATE | Native.PROCESS_QUERY_LIMITED_INFORMATION, false, proc.Pid);
        if (handle == 0)
        {
            var error = Marshal.GetLastPInvokeError();
            return Gone(proc) ? null : Marshal.GetPInvokeErrorMessage(error);
        }
        try
        {
            // It already ended, and the ID belongs to something else now.
            if (proc.Started != 0 && CreationTime(handle) != proc.Started) return null;
            if (Native.TerminateProcess(handle, 1)) return null;
            var error = Marshal.GetLastPInvokeError();
            // A process already on its way out (a console host whose program just ended,
            // say) refuses to be ended again. That's not a failure.
            return Native.GetExitCodeProcess(handle, out var code) && code != Native.STILL_ACTIVE
                ? null : Marshal.GetPInvokeErrorMessage(error);
        }
        finally
        {
            Native.CloseHandle(handle);
        }
    }

    /// <summary>Whether a process has ended since it was listed: its ID is free, or belongs
    /// to a later process, or it's exiting.</summary>
    static bool Gone(Proc proc)
    {
        var handle = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, proc.Pid);
        if (handle == 0) return Marshal.GetLastPInvokeError() == 87; // ERROR_INVALID_PARAMETER: no such process
        try
        {
            return (proc.Started != 0 && CreationTime(handle) != proc.Started)
                || (Native.GetExitCodeProcess(handle, out var code) && code != Native.STILL_ACTIVE);
        }
        finally
        {
            Native.CloseHandle(handle);
        }
    }

    /// <summary>
    /// Ends <paramref name="roots"/> and everything they started. Parents go first, so
    /// nothing is left to restart a child; then it looks again, a few times, for
    /// processes started in the meantime. Never ends <paramref name="spare"/>.
    /// </summary>
    public static (int Killed, List<string> Errors) KillTree(IReadOnlyList<Proc> roots, uint spare)
    {
        var killed = new HashSet<(uint, long)>();
        var errors = new List<string>();
        var rootIds = roots.Select(p => p.Pid).ToHashSet();
        var procs = List();
        var targets = new List<Proc>(roots);
        for (var pass = 0; pass < 3; pass++)
        {
            var below = Descendants(procs, rootIds);
            targets.AddRange(procs.Where(p => below.Contains(p.Pid)));
            targets.RemoveAll(p => p.Pid == spare || killed.Contains((p.Pid, p.Started)));
            if (targets.Count == 0) break;
            foreach (var proc in targets)
            {
                if (Kill(proc) is { } error) errors.Add($"{proc.Name} ({proc.Pid}): {error}");
                else killed.Add((proc.Pid, proc.Started));
            }
            targets.Clear();
            rootIds.UnionWith(killed.Select(k => k.Item1));
            Thread.Sleep(150);
            procs = List();
        }
        return (killed.Count, errors.Distinct().ToList());
    }

    [ThreadStatic] static HashSet<uint>? windowOwners;

    /// <summary>The processes that own a window a person can see: visible, not hidden away
    /// by the shell, not a tool window or an owned popup, and titled.</summary>
    public static HashSet<uint> WithWindows()
    {
        windowOwners = [];
        Native.EnumWindows(&Visit, 0);
        var result = windowOwners;
        windowOwners = null;
        return result;
    }

    [UnmanagedCallersOnly]
    static int Visit(nint hwnd, nint lParam)
    {
        if (!Native.IsWindowVisible(hwnd) || Native.GetWindowTextLengthW(hwnd) == 0) return 1;
        if (Native.GetWindow(hwnd, Native.GW_OWNER) != 0) return 1;
        if ((Native.GetWindowLongW(hwnd, Native.GWL_EXSTYLE) & Native.WS_EX_TOOLWINDOW) != 0) return 1;
        if (Native.DwmGetWindowAttribute(hwnd, Native.DWMWA_CLOAKED, out var cloaked, 4) == 0 && cloaked != 0) return 1;
        Native.GetWindowThreadProcessId(hwnd, out var pid);
        windowOwners?.Add(pid);
        return 1;
    }

    /// <summary>A FILETIME count as a local DateTimeOffset.</summary>
    public static DateTimeOffset Time(long filetime) => DateTimeOffset.FromFileTime(filetime);
}
