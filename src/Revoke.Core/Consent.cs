using Microsoft.Win32;

namespace Revoke.Core;

public enum Capability
{
    /// <summary>Taking screenshots of other apps, and doing it without the yellow border.</summary>
    ScreenCapture,
    Camera,
    Microphone,
    Location,
}

public enum Access
{
    /// <summary>Not in the list.</summary>
    Unset,
    Denied,
    /// <summary>Windows asks the next time the app wants it.</summary>
    Ask,
    Allowed,
}

/// <param name="Access">For a packaged app, its own switch. For a desktop program, the
/// switch all desktop programs share.</param>
/// <param name="Shared">Whether this is the shared desktop-apps switch rather than the app's own.</param>
/// <param name="InUse">Using it right now: Windows records a start and no stop yet.</param>
public sealed record ConsentEntry(Access Access, bool Shared, bool InUse, DateTimeOffset? LastUsed);

/// <summary>
/// The privacy switches in Settings › Privacy &amp; security, which Windows keeps in the
/// CapabilityAccessManager consent store. Packaged apps get a switch each, which
/// Revoke can turn off. Desktop programs share one switch per capability ("Let
/// desktop apps access your camera"), so for them Revoke can show when they use it,
/// but not switch off one alone.
/// </summary>
public static class Consent
{
    const string Store = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    public static readonly Capability[] All = [Capability.ScreenCapture, Capability.Camera, Capability.Microphone, Capability.Location];

    /// <summary>The consent store's names for it.</summary>
    public static string[] Keys(Capability capability) => capability switch
    {
        Capability.ScreenCapture => ["graphicsCaptureProgrammatic", "graphicsCaptureWithoutBorder"],
        Capability.Camera => ["webcam"],
        Capability.Microphone => ["microphone"],
        _ => ["location"],
    };

    public static string SettingsUri(Capability capability) => capability switch
    {
        Capability.ScreenCapture => "ms-settings:privacy-graphicsCaptureProgrammatic",
        Capability.Camera => "ms-settings:privacy-webcam",
        Capability.Microphone => "ms-settings:privacy-microphone",
        _ => "ms-settings:privacy-location",
    };

    public sealed class Snapshot
    {
        public Dictionary<Client, Dictionary<Capability, ConsentEntry>> Entries { get; } = [];

        /// <summary>Whether the capability is switched on for apps at all, for this user and the PC.</summary>
        public Dictionary<Capability, bool> GloballyOn { get; } = [];
    }

    static Access Parse(object? value) => (value as string) switch
    {
        "Allow" => Access.Allowed,
        "Deny" => Access.Denied,
        "Prompt" => Access.Ask,
        _ => Access.Unset,
    };

    public static Snapshot Read()
    {
        var snapshot = new Snapshot();
        foreach (var capability in All)
        {
            var globallyOn = false;
            foreach (var name in Keys(capability))
            {
                using var user = Registry.CurrentUser.OpenSubKey($@"{Store}\{name}");
                using var machine = Registry.LocalMachine.OpenSubKey($@"{Store}\{name}");
                globallyOn |= Parse(user?.GetValue("Value")) != Access.Denied && Parse(machine?.GetValue("Value")) != Access.Denied;
                if (user is null) continue;

                using var desktop = user.OpenSubKey("NonPackaged");
                var desktopAccess = Parse(desktop?.GetValue("Value")) is var a && a != Access.Unset ? a : Access.Allowed;

                foreach (var family in user.GetSubKeyNames().Where(k => k != "NonPackaged"))
                {
                    using var key = user.OpenSubKey(family);
                    if (key is not null) Merge(snapshot, Client.Package(family), capability, Parse(key.GetValue("Value")), key, false);
                }
                if (desktop is null) continue;
                foreach (var encoded in desktop.GetSubKeyNames())
                {
                    using var key = desktop.OpenSubKey(encoded);
                    if (key is null) continue;
                    // Paths are stored with # in place of \.
                    var client = Client.FromPath(encoded.Replace('#', '\\'));
                    var shared = client.Family is null;
                    Merge(snapshot, client, capability, shared ? desktopAccess : Access.Unset, key, shared);
                }
            }
            snapshot.GloballyOn[capability] = globallyOn;
        }
        return snapshot;
    }

    /// <summary>Folds one consent store key into an entry. Screen capture has two keys, and a
    /// packaged desktop app can show up both under its family and as a path.</summary>
    static void Merge(Snapshot snapshot, Client client, Capability capability, Access access, RegistryKey key, bool shared)
    {
        if (!snapshot.Entries.TryGetValue(client, out var entries)) snapshot.Entries[client] = entries = [];
        var entry = entries.GetValueOrDefault(capability) ?? new ConsentEntry(Access.Unset, false, false, null);
        if (access > entry.Access) entry = entry with { Access = access, Shared = shared };
        var start = key.GetValue("LastUsedTimeStart") is long s ? s : 0;
        var stop = key.GetValue("LastUsedTimeStop") is long t ? t : 0;
        if (start != 0 && stop == 0) entry = entry with { InUse = true };
        if (stop != 0)
        {
            var stopped = DateTimeOffset.FromFileTime(stop);
            entry = entry with { LastUsed = entry.LastUsed is { } last && last > stopped ? last : stopped };
        }
        entries[capability] = entry;
    }

    /// <summary>Switches a packaged app's access off. Windows only stops new uses: a camera
    /// already streaming keeps streaming until the app lets go, which stopping the app makes happen.</summary>
    public static void Deny(string family, Capability capability)
    {
        foreach (var name in Keys(capability))
        {
            using var key = Registry.CurrentUser.CreateSubKey($@"{Store}\{name}\{family}");
            key.SetValue("Value", "Deny", RegistryValueKind.String);
        }
    }
}
