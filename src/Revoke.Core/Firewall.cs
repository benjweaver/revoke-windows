using Microsoft.Win32;

namespace Revoke.Core;

/// <param name="Id">The rule's ID, which Set-NetFirewallRule -Name takes.</param>
public sealed record FirewallRule(string Id, string Name, bool Inbound, bool Allow, bool Active, string? Program, string? Description, string? Group)
{
    /// <summary>The client a rule Revoke added is for.</summary>
    public Client? RevokeClient =>
        Group == Firewall.Group && Description?.StartsWith(Firewall.DescriptionPrefix, StringComparison.Ordinal) == true
            ? Client.FromKey(Description[Firewall.DescriptionPrefix.Length..])
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
public static class Firewall
{
    const string Rules = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

    /// <summary>Rules Revoke adds carry this group, and a description naming the client.</summary>
    public const string Group = "Revoke";
    public const string DescriptionPrefix = "revoke:";

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
                "App" => rule with { Program = Environment.ExpandEnvironmentVariables(value) },
                "Name" => rule with { Name = value },
                "Desc" => rule with { Description = value },
                "EmbedCtxt" => rule with { Group = value },
                _ => rule,
            };
        }
        return rule;
    }
}
