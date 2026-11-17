using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace Revoke.Core;

/// <param name="Id">The rule's ID, which Set-NetFirewallRule -Name takes.</param>
public sealed record FirewallRule(string Id, string Name, bool Inbound, bool Allow, bool Active, string? Program, string? Description, string? Group)
{
    public int? Protocol { get; init; }
    /// <summary>The client a rule Revoke added is for.</summary>
    public Client? RevokeClient =>
        Group == Firewall.Group && Description?.StartsWith(Firewall.DescriptionPrefix, StringComparison.Ordinal) == true
            ? Client.FromKey(Description[Firewall.DescriptionPrefix.Length..])
            : null;

    /// <summary>The client an internet-host allowlist rule Revoke added is for.</summary>
    public Client? RevokeInternetClient =>
        Group == Firewall.Group && Description?.StartsWith(Firewall.InternetDescriptionPrefix, StringComparison.Ordinal) == true
            ? Client.FromKey(Description[Firewall.InternetDescriptionPrefix.Length..])
            : null;
}

/// <summary>
/// Windows Firewall rules, read from where Windows keeps them. Reading needs no
/// admin rights; changing them does, so changes go through <see cref="Elevated"/>.
///
/// An app that asked to "allow access" on first launch has inbound rules that let
/// any device on the network connect to it. Revoke switches those off, and adds
/// outbound rules that keep the app's programs from connecting to devices on the
/// local network. The internet stays reachable, and so does DNS, which apps built
/// on Chromium send straight to the router.
/// </summary>
public static partial class Firewall
{
    const string Rules = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

    /// <summary>Rules Revoke adds carry this group, and a description naming the client.</summary>
    public const string Group = "Revoke";
    public const string DescriptionPrefix = "revoke:";
    public const string InternetDescriptionPrefix = "revoke-internet:";

    /// <summary>Private, link-local, multicast and broadcast addresses: the local network as
    /// macOS defines it. "LocalSubnet" is the firewall's name for the subnets this PC is
    /// on, which can be outside the private ranges.</summary>
    public static readonly string[] LocalAddresses =
    [
        "LocalSubnet", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "224.0.0.0/4", "255.255.255.255", "fc00::/7", "fe80::/10", "ff00::/8",
    ];

    /// <summary>Every port but DNS.</summary>
    public const string Ports = "1-52,54-65535";

    /// <summary>Windows Firewall rules only accept fully-qualified .exe paths (not e.g. Inno Setup .tmp updaters).</summary>
    public static bool IsExecutable(string? path) =>
        !string.IsNullOrWhiteSpace(path) &&
        Path.IsPathFullyQualified(path) &&
        string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase);

    /// <summary>Windows can report a running program through an 8.3 path. Expand it
    /// before giving it to the firewall, which may reject the short form.</summary>
    internal static unsafe string LongProgramPath(string path)
    {
        Span<char> buffer = stackalloc char[512];
        fixed (char* chars = buffer)
        {
            var length = GetLongPathNameW(path, chars, (uint)buffer.Length);
            if (length is > 0 and < 512) return new string(chars, 0, (int)length);
            if (length == 0) return path;
            var larger = new char[length];
            fixed (char* longChars = larger)
            {
                var retry = GetLongPathNameW(path, longChars, (uint)larger.Length);
                return retry is > 0 && retry < larger.Length
                    ? new string(longChars, 0, (int)retry) : path;
            }
        }
    }

    [LibraryImport("kernel32.dll", EntryPoint = "GetLongPathNameW", StringMarshalling = StringMarshalling.Utf16)]
    private static unsafe partial uint GetLongPathNameW(string shortPath, char* longPath, uint size);

    /// <summary>Programs with active outbound block rules for both TCP and UDP.</summary>
    internal static HashSet<string> FullyBlockedPrograms(IEnumerable<FirewallRule> rules)
    {
        var protocols = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in rules)
        {
            if (!IsActiveBlock(rule) || rule.Program is null) continue;
            protocols.TryGetValue(rule.Program, out var covered);
            protocols[rule.Program] = covered | (rule.Protocol == 6 ? 1 : 2);
        }
        return protocols.Where(pair => pair.Value == 3)
            .Select(pair => pair.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>The protocols a program still needs for one client's set of rules.</summary>
    internal static int[] MissingBlockProtocols(string program, IEnumerable<FirewallRule> rules)
    {
        var covered = rules.Where(r => IsActiveBlock(r)
                && string.Equals(r.Program, program, StringComparison.OrdinalIgnoreCase))
            .Select(r => r.Protocol).ToHashSet();
        return new[] { 6, 17 }.Where(protocol => !covered.Contains(protocol)).ToArray();
    }

    static bool IsActiveBlock(FirewallRule rule) =>
        rule.Active && !rule.Inbound && !rule.Allow && rule.Protocol is 6 or 17;

    /// <summary>Tells when a rule in the local policy store is added, changed, or removed.</summary>
    public static RegistryWatch Watch() => new(Registry.LocalMachine, Rules, subtree: false);

    /// <summary>The rules in the local policy store, where Windows Defender Firewall's own
    /// settings and apps' "Allow access" prompts write. Null if it can't be read.</summary>
    public static List<FirewallRule>? Read()
    {
        using var key = Registry.LocalMachine.OpenSubKey(Rules);
        if (key is null) return null;
        return key.GetValueNames()
            .Select(id => key.GetValue(id) is string text ? Parse(id, text) : null)
            .OfType<FirewallRule>()
            .ToList();
    }

    /// <summary>Parses "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=C:\…|Name=Claude|…".</summary>
    internal static FirewallRule Parse(string id, string text)
    {
        var rule = new FirewallRule(id, "", false, false, false, null, null, null);
        foreach (var field in text.Split('|').Skip(1))
        {
            var eq = field.IndexOf('=');
            if (eq < 0) continue;
            var value = field[(eq + 1)..];
            rule = field[..eq] switch
            {
                "Action" => rule with { Allow = value == "Allow" },
                "Active" => rule with { Active = value == "TRUE" },
                "Dir" => rule with { Inbound = value == "In" },
                "Protocol" when int.TryParse(value, out var protocol) => rule with { Protocol = protocol },
                "App" => rule with { Program = LongProgramPath(Environment.ExpandEnvironmentVariables(value)) },
                "Name" => rule with { Name = value },
                "Desc" => rule with { Description = value },
                "EmbedCtxt" => rule with { Group = value },
                _ => rule,
            };
        }
        return rule;
    }
}
