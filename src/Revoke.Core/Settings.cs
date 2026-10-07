using System.Text.Json;

namespace Revoke.Core;

/// <summary>Preferences, kept in %APPDATA%\Revoke\settings.json. Nothing leaves the PC.</summary>
public sealed class Settings
{
    /// <summary>Apps from these developers are watched unless unchecked.</summary>
    public static readonly string[] WatchedVendors = ["anthropic", "openai"];
    public static readonly int[] TimeLimits = [15, 30, 60, 120, 240];

    /// <summary>Stop a watched app, and revoke its access, once its last window closes,
    /// rather than leaving it in the notification area.</summary>
    public bool RevokeOnClose { get; set; }
    public bool RevokeAfterLimit { get; set; }
    public int LimitMinutes { get; set; } = 30;
    public bool RevokeOnLock { get; set; }
    /// <summary>Watched apps from other developers, by client key.</summary>
    public HashSet<string> Added { get; set; } = [];
    /// <summary>Unwatched apps from the watched developers, by client key.</summary>
    public HashSet<string> Removed { get; set; } = [];
    /// <summary>Inbound rules Revoke switched off, by client key, to switch back on later.</summary>
    public Dictionary<string, List<string>> DisabledRules { get; set; } = [];
    /// <summary>How services started before Revoke changed them.</summary>
    public Dictionary<string, int> ServiceStarts { get; set; } = [];
    /// <summary>The time limit never counts from before it was switched on.</summary>
    public DateTimeOffset LimitStart { get; set; }
    /// <summary>Settings open by themselves only the first time, to set Revoke up.</summary>
    public bool SetUp { get; set; }

    static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static string FilePath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Revoke", "settings.json");

    public static Settings Load()
    {
        Settings settings;
        try
        {
            settings = JsonSerializer.Deserialize<Settings>(File.ReadAllText(FilePath), Json) ?? new();
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            settings = new();
        }
        if (!TimeLimits.Contains(settings.LimitMinutes)) settings.LimitMinutes = 30;
        return settings;
    }

    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        // Written whole and then moved into place, so a crash can't leave half a file.
        var temp = FilePath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(this, Json));
        File.Move(temp, FilePath, overwrite: true);
    }

    public static bool WatchedByDefault(string publisher) => WatchedVendors.Contains(Client.VendorKey(publisher));

    public bool IsWatched(Client client, string publisher) =>
        !Removed.Contains(client.Key) && (Added.Contains(client.Key) || WatchedByDefault(publisher));

    public void SetWatched(Client client, string publisher, bool watched)
    {
        var byDefault = WatchedByDefault(publisher);
        if (watched)
        {
            Removed.Remove(client.Key);
            if (!byDefault) Added.Add(client.Key);
        }
        else
        {
            Added.Remove(client.Key);
            if (byDefault) Removed.Add(client.Key);
        }
    }

    public void SetRevokeAfterLimit(bool on)
    {
        // Count from now, so switching this on doesn't stop an app that has been running
        // for hours on the spot.
        if (on && !RevokeAfterLimit) LimitStart = DateTimeOffset.Now;
        RevokeAfterLimit = on;
    }

    public static string Describe(int minutes) => minutes switch
    {
        < 60 => $"{minutes} minutes",
        60 => "1 hour",
        _ => $"{minutes / 60} hours",
    };
}
