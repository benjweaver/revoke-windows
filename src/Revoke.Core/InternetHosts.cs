using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace Revoke.Core;

/// <summary>
/// Model providers' own internet hosts, host name normalization and matching, DNS
/// resolution, and complement IP range computation for outbound Windows Firewall rules.
/// </summary>
public static class InternetHosts
{
    public static readonly IReadOnlyDictionary<string, string[]> BuiltIn = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
    {
        ["anthropic"] = ["anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com"],
        ["openai"] = ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"],
        ["anysphere"] = ["cursor.sh", "cursor.com", "cursorapi.com", "cursor-cdn.com"],
        ["deepseek"] = ["deepseek.com"],
        ["antigravity"] =
        [
            "antigravity.google",
            "accounts.google.com",
            "oauth2.googleapis.com",
            "www.googleapis.com",
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
        ],
    };

    static readonly string[] KnownSubdomains =
    [
        "api.anthropic.com",
        "a-api.anthropic.com",
        "api.openai.com",
        "auth.openai.com",
        "auth0.openai.com",
        "platform.openai.com",
        "ab.chatgpt.com",
        "ws.chatgpt.com",
        "ios.chat.openai.com",
        "cdn.oaistatic.com",
        "files.oaiusercontent.com",
        "api2.cursor.sh",
        "api3.cursor.sh",
        "api4.cursor.sh",
        "repo42.cursor.sh",
        "api.cursor.com",
        "marketplace.cursorapi.com",
        "api.deepseek.com",
        "chat.deepseek.com",
        "cdn.deepseek.com",
        "oauth2.googleapis.com",
        "www.googleapis.com",
        "cloudcode-pa.googleapis.com",
        "daily-cloudcode-pa.googleapis.com",
        "generativelanguage.googleapis.com",
    ];

    static readonly string[] CommonPrefixes = ["api.", "www.", "auth.", "cdn.", "ws.", "files.", "chat."];

    static readonly (uint Start, uint End)[] NonInternetIpv4 =
    [
        Ipv4Cidr(0x00_00_00_00u, 8),   // 0.0.0.0/8
        Ipv4Cidr(0x0A_00_00_00u, 8),   // 10.0.0.0/8
        Ipv4Cidr(0x7F_00_00_00u, 8),   // 127.0.0.0/8
        Ipv4Cidr(0xA9_FE_00_00u, 16),  // 169.254.0.0/16
        Ipv4Cidr(0xAC_10_00_00u, 12),  // 172.16.0.0/12
        Ipv4Cidr(0xC0_A8_00_00u, 16),  // 192.168.0.0/16
        (0xE0_00_00_00u, 0xFF_FF_FF_FFu), // 224.0.0.0-255.255.255.255
    ];

    static readonly (UInt128 Start, UInt128 End)[] NonInternetIpv6 =
    [
        (UInt128.Zero, UInt128.Zero), // ::/128
        (UInt128.One, UInt128.One),   // ::1/128
        Ipv6Cidr(new UInt128(0xFC00_0000_0000_0000UL, 0UL), 7),  // fc00::/7
        Ipv6Cidr(new UInt128(0xFE80_0000_0000_0000UL, 0UL), 10), // fe80::/10
        Ipv6Cidr(new UInt128(0xFF00_0000_0000_0000UL, 0UL), 8),  // ff00::/8
    ];

    /// <summary>The allowed internet hosts for an app: its developer's built-in hosts plus
    /// <paramref name="extraHosts"/>, normalized, distinct, and sorted.</summary>
    public static List<string> ForClient(Client client, string publisher, IEnumerable<string> extraHosts)
    {
        var vendor = Client.VendorKey(publisher);
        if (!BuiltIn.TryGetValue(vendor, out var own))
        {
            if (vendor.Equals("cursor", StringComparison.OrdinalIgnoreCase) || IsClientNamed(client, "cursor"))
                own = BuiltIn["anysphere"];
            else if (vendor.Equals("google", StringComparison.OrdinalIgnoreCase) || IsClientNamed(client, "antigravity"))
                own = BuiltIn["antigravity"];
            else
                own = [];
        }

        return own
            .Concat((extraHosts ?? []).Select(Normalized).OfType<string>())
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();
    }

    static bool IsClientNamed(Client client, string name) =>
        client.Kind == ClientKind.Exe
        && (client.Id.Split('\\')[..^1].Any(f => f.Equals(name, StringComparison.OrdinalIgnoreCase))
            || Path.GetFileNameWithoutExtension(client.Id).Equals(name, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Normalizes a domain or host name (lowercases, strips scheme, path, port, leading
    /// <c>*.</c> / <c>.</c> and trailing <c>.</c>, and validates DNS labels). Returns
    /// <see langword="null"/> for single-label names, IP literals, or invalid labels.
    /// </summary>
    public static string? Normalized(string name)
    {
        if (string.IsNullOrEmpty(name)) return null;
        var s = name.Trim().ToLowerInvariant();

        var scheme = s.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) s = s[(scheme + 3)..];

        var cut = s.IndexOfAny(['/', ':']);
        if (cut >= 0) s = s[..cut];

        while (true)
        {
            if (s.StartsWith("*.", StringComparison.Ordinal)) s = s[2..];
            else if (s.StartsWith('.')) s = s[1..];
            else break;
        }
        while (s.EndsWith('.')) s = s[..^1];

        if (s.Length == 0 || Encoding.UTF8.GetByteCount(s) > 253) return null;

        var labels = s.Split('.');
        if (labels.Length < 2) return null;

        foreach (var label in labels)
        {
            if (label.Length is < 1 or > 63) return null;
            if (label.StartsWith('-') || label.EndsWith('-')) return null;
            foreach (var c in label)
            {
                if (c is not ((>= 'a' and <= 'z') or (>= '0' and <= '9') or '-'))
                    return null;
            }
        }

        if (labels[^1].All(char.IsAsciiDigit)) return null;

        return s;
    }

    /// <summary>Splits comma- or whitespace-separated host names, normalizes each, and
    /// deduplicates while preserving order.</summary>
    public static List<string> Parse(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return [];
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<string>();
        foreach (var token in text.Split(c => c == ',' || char.IsWhiteSpace(c)))
        {
            if (Normalized(token) is { } host && seen.Add(host))
                result.Add(host);
        }
        return result;
    }

    /// <summary>Whether <paramref name="name"/> is one of <paramref name="allowed"/> or a
    /// subdomain of one.</summary>
    public static bool Matches(string name, IEnumerable<string> allowed)
    {
        if (Normalized(name) is not { } host || allowed is null) return false;
        foreach (var raw in allowed)
        {
            if (Normalized(raw) is { } domain
                && (host == domain || host.EndsWith("." + domain, StringComparison.Ordinal)))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Computes the IPv4 and IPv6 address ranges for an outbound Windows Firewall Block rule's
    /// <c>RemoteAddresses</c>: the complement of all non-Internet ranges, local subnets, and
    /// <paramref name="allowedIps"/>.
    /// </summary>
    public static List<string> ComplementRanges(
        IEnumerable<IPAddress> allowedIps,
        IEnumerable<(IPAddress Address, int PrefixLength)>? localSubnets = null)
    {
        var excludedV4 = new List<(uint Start, uint End)>(NonInternetIpv4);
        var excludedV6 = new List<(UInt128 Start, UInt128 End)>(NonInternetIpv6);

        foreach (var (rawAddress, prefixLength) in localSubnets ?? ActiveLocalSubnets())
        {
            if (rawAddress is null) continue;
            var address = rawAddress.IsIPv4MappedToIPv6 ? rawAddress.MapToIPv4() : rawAddress;
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                var p = rawAddress.IsIPv4MappedToIPv6 && prefixLength >= 96 ? prefixLength - 96 : prefixLength;
                excludedV4.Add(Ipv4Cidr(ToUInt32(address), Math.Clamp(p, 0, 32)));
            }
            else if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                excludedV6.Add(Ipv6Cidr(ToUInt128(address), Math.Clamp(prefixLength, 0, 128)));
            }
        }

        if (allowedIps is not null)
        {
            foreach (var rawIp in allowedIps)
            {
                if (rawIp is null) continue;
                var ip = rawIp.IsIPv4MappedToIPv6 ? rawIp.MapToIPv4() : rawIp;
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    var v = ToUInt32(ip);
                    excludedV4.Add((v, v));
                }
                else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    var v = ToUInt128(ip);
                    excludedV6.Add((v, v));
                }
            }
        }

        var ranges = new List<string>();
        AppendComplementV4(excludedV4, ranges);
        AppendComplementV6(excludedV6, ranges);
        return ranges;
    }

    /// <summary>
    /// Expands <paramref name="allowedDomains"/> into candidate host names for DNS resolution:
    /// exact entries, matching known provider subdomains, and common prefixes on bare domains.
    /// </summary>
    internal static HashSet<string> CandidateHosts(IEnumerable<string> allowedDomains)
    {
        if (allowedDomains is null) return [];
        var domains = allowedDomains
            .Select(Normalized)
            .OfType<string>()
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (domains.Count == 0) return [];

        var candidates = new HashSet<string>(domains, StringComparer.Ordinal);
        foreach (var sub in KnownSubdomains)
        {
            if (Matches(sub, domains))
                candidates.Add(sub);
        }
        foreach (var domain in domains)
        {
            if (!IsBareDomain(domain)) continue;
            foreach (var prefix in CommonPrefixes)
            {
                if (Normalized(prefix + domain) is { } sub)
                    candidates.Add(sub);
            }
        }
        return candidates;
    }

    static bool IsBareDomain(string domain)
    {
        var firstDot = domain.IndexOf('.');
        return firstDot > 0 && firstDot == domain.LastIndexOf('.');
    }

    /// <summary>
    /// Resolves <paramref name="allowedDomains"/>, known provider subdomains, common
    /// prefixes into IP addresses.
    /// </summary>
    public static List<IPAddress> ResolveAllowedIps(IEnumerable<string> allowedDomains)
    {
        var candidates = CandidateHosts(allowedDomains);
        if (candidates.Count == 0) return [];

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        var token = cts.Token;
        var resolved = candidates.Select(async host =>
        {
            try
            {
                return await Dns.GetHostAddressesAsync(host, token).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ArgumentException or OperationCanceledException)
            {
                return [];
            }
        }).ToArray();

        var all = Task.WhenAll(resolved).GetAwaiter().GetResult();
        var seen = new HashSet<IPAddress>();
        var result = new List<IPAddress>();
        foreach (var addresses in all)
        {
            foreach (var raw in addresses)
            {
                var ip = raw.IsIPv4MappedToIPv6 ? raw.MapToIPv4() : raw;
                if (IsUsableInternetIp(ip) && seen.Add(ip))
                    result.Add(ip);
            }
        }

        result.Sort(CompareIpAddresses);
        return result;
    }

    static bool IsUsableInternetIp(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return false;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            Span<byte> b = stackalloc byte[4];
            ip.TryWriteBytes(b, out _);
            if (b[0] == 0 || b[0] == 127) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] >= 224) return false;
            return true;
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6Loopback)) return false;
            if (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal) return false;
            return true;
        }
        return false;
    }

    static int CompareIpAddresses(IPAddress a, IPAddress b)
    {
        if (a.AddressFamily != b.AddressFamily)
            return a.AddressFamily == AddressFamily.InterNetwork ? -1 : 1;
        return a.AddressFamily == AddressFamily.InterNetwork
            ? ToUInt32(a).CompareTo(ToUInt32(b))
            : ToUInt128(a).CompareTo(ToUInt128(b));
    }

    static List<(IPAddress Address, int PrefixLength)> ActiveLocalSubnets()
    {
        var subnets = new List<(IPAddress Address, int PrefixLength)>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up
                    || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    continue;
                }
                foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                {
                    var addr = unicast.Address;
                    if (addr.AddressFamily == AddressFamily.InterNetwork && unicast.PrefixLength is >= 8 and <= 32)
                        subnets.Add((addr, unicast.PrefixLength));
                    else if (addr.AddressFamily == AddressFamily.InterNetworkV6 && unicast.PrefixLength is >= 48 and <= 128)
                        subnets.Add((addr, unicast.PrefixLength));
                }
            }
        }
        catch (Exception e) when (e is NetworkInformationException or PlatformNotSupportedException)
        {
        }
        return subnets;
    }

    static (uint Start, uint End) Ipv4Cidr(uint address, int prefixLength)
    {
        if (prefixLength <= 0) return (0u, uint.MaxValue);
        if (prefixLength >= 32) return (address, address);
        var mask = uint.MaxValue << (32 - prefixLength);
        var start = address & mask;
        return (start, start | ~mask);
    }

    static (UInt128 Start, UInt128 End) Ipv6Cidr(UInt128 address, int prefixLength)
    {
        if (prefixLength <= 0) return (UInt128.MinValue, UInt128.MaxValue);
        if (prefixLength >= 128) return (address, address);
        var mask = UInt128.MaxValue << (128 - prefixLength);
        var start = address & mask;
        return (start, start | ~mask);
    }

    static void AppendComplementV4(List<(uint Start, uint End)> excluded, List<string> output)
    {
        excluded.Sort((a, b) => a.Start != b.Start ? a.Start.CompareTo(b.Start) : a.End.CompareTo(b.End));

        var merged = new List<(uint Start, uint End)>(excluded.Count);
        foreach (var interval in excluded)
        {
            if (merged.Count == 0)
            {
                merged.Add(interval);
                continue;
            }
            var last = merged[^1];
            if (interval.Start <= last.End || interval.Start - last.End == 1u)
            {
                if (interval.End > last.End)
                    merged[^1] = (last.Start, interval.End);
            }
            else
            {
                merged.Add(interval);
            }
        }

        uint cursor = 0u;
        foreach (var (start, end) in merged)
        {
            if (start > cursor)
                output.Add(FormatRangeV4(cursor, start - 1u));
            if (end == uint.MaxValue)
                return;
            cursor = end + 1u;
        }
        output.Add(FormatRangeV4(cursor, uint.MaxValue));
    }

    static void AppendComplementV6(List<(UInt128 Start, UInt128 End)> excluded, List<string> output)
    {
        excluded.Sort((a, b) => a.Start != b.Start ? a.Start.CompareTo(b.Start) : a.End.CompareTo(b.End));

        var merged = new List<(UInt128 Start, UInt128 End)>(excluded.Count);
        foreach (var interval in excluded)
        {
            if (merged.Count == 0)
            {
                merged.Add(interval);
                continue;
            }
            var last = merged[^1];
            if (interval.Start <= last.End || interval.Start - last.End == UInt128.One)
            {
                if (interval.End > last.End)
                    merged[^1] = (last.Start, interval.End);
            }
            else
            {
                merged.Add(interval);
            }
        }

        var cursor = UInt128.MinValue;
        foreach (var (start, end) in merged)
        {
            if (start > cursor)
                output.Add(FormatRangeV6(cursor, start - UInt128.One));
            if (end == UInt128.MaxValue)
                return;
            cursor = end + UInt128.One;
        }
        output.Add(FormatRangeV6(cursor, UInt128.MaxValue));
    }

    static string FormatRangeV4(uint start, uint end) =>
        start == end ? FromUInt32(start).ToString() : $"{FromUInt32(start)}-{FromUInt32(end)}";

    static string FormatRangeV6(UInt128 start, UInt128 end) =>
        start == end ? FromUInt128(start).ToString() : $"{FromUInt128(start)}-{FromUInt128(end)}";

    static uint ToUInt32(IPAddress ip)
    {
        Span<byte> bytes = stackalloc byte[4];
        ip.TryWriteBytes(bytes, out _);
        return BinaryPrimitives.ReadUInt32BigEndian(bytes);
    }

    static IPAddress FromUInt32(uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return new IPAddress(bytes);
    }

    static UInt128 ToUInt128(IPAddress ip)
    {
        Span<byte> bytes = stackalloc byte[16];
        ip.TryWriteBytes(bytes, out _);
        return BinaryPrimitives.ReadUInt128BigEndian(bytes);
    }

    static IPAddress FromUInt128(UInt128 value)
    {
        Span<byte> bytes = stackalloc byte[16];
        BinaryPrimitives.WriteUInt128BigEndian(bytes, value);
        return new IPAddress(bytes);
    }

}
