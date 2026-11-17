using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace Revoke.Core;

/// <summary>
/// What an agent asks Revoke for with a link or <c>Revoke --request</c>: one kind of
/// access, for a while, and why.
/// <code>
///     Revoke --request "revoke://request?access=local-network&amp;minutes=15&amp;reason=Reach%20the%20test%20VM"
/// </code>
/// An agent that finds something blocked can ask this way instead of working around the
/// block. Revoke shows the person who's asking and for what, and nothing changes unless
/// they say yes. Who sent it is worked out from the process that asked, never from what
/// the link says, and the reason is shown as text.
/// </summary>
public sealed record AccessRequest(Pane Pane, int Minutes, string? Reason, string? ClaimedApp)
{
    public const string Scheme = "revoke";
    public const string RequestFlag = "--request";
    public const string RequestUrlFlag = "--request-url";
    public const int DefaultMinutes = 15;
    public const int MaxMinutes = 240;
    public const int ReasonLimit = 300;
    public const int MaxUrlChars = 4096;

    /// <summary>The names a link uses for each kind of access Revoke can be asked for.
    /// Running, Startup, Service, and Links aren't here: an agent has no business
    /// switching those on for itself.</summary>
    public static readonly IReadOnlyDictionary<string, Pane> Names = new Dictionary<string, Pane>(StringComparer.OrdinalIgnoreCase)
    {
        ["local-network"] = Pane.Network,
        ["internet"] = Pane.Internet,
        ["screen"] = Pane.Screen,
        ["screen-recording"] = Pane.Screen,
        ["camera"] = Pane.Camera,
        ["microphone"] = Pane.Microphone,
        ["location"] = Pane.Location,
    };

    public static string PipeName =>
        $"dev.benjweaver.Revoke.Request.{WindowsIdentity.GetCurrent().User?.Value ?? "user"}";

    /// <summary>Whether a link is addressed to Revoke itself.</summary>
    public static bool IsRequestUrl(string? text) =>
        Uri.TryCreate(text, UriKind.Absolute, out var uri)
        && uri.Scheme.Equals(Scheme, StringComparison.OrdinalIgnoreCase);

    /// <summary>Parses a <c>revoke://request?…</c> link, or returns null for anything malformed.</summary>
    public static AccessRequest? Parse(string? text)
    {
        if (text is null || text.Length > MaxUrlChars) return null;
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri)) return null;
        if (!uri.Scheme.Equals(Scheme, StringComparison.OrdinalIgnoreCase)) return null;
        if (!uri.Host.Equals("request", StringComparison.OrdinalIgnoreCase)) return null;

        // The first of each name counts, so a second one can't override what was shown.
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var query = uri.Query.TrimStart('?');
        if (query.Length > 0)
        {
            foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = part.IndexOf('=');
                var rawName = eq >= 0 ? part[..eq] : part;
                var rawValue = eq >= 0 ? part[(eq + 1)..] : "";
                var name = UnescapeQuery(rawName);
                if (!values.ContainsKey(name))
                    values[name] = UnescapeQuery(rawValue).Trim();
            }
        }

        if (!values.TryGetValue("access", out var access) || !Names.TryGetValue(access, out var pane))
            return null;

        var minutes = DefaultMinutes;
        if (values.TryGetValue("minutes", out var minsText) && int.TryParse(minsText, out var parsedMinutes))
            minutes = Math.Clamp(parsedMinutes, 1, MaxMinutes);

        string? reason = null;
        if (values.TryGetValue("reason", out var rawReason) && rawReason.Length > 0)
        {
            var capped = new StringBuilder();
            var count = 0;
            foreach (var rune in rawReason.EnumerateRunes())
            {
                if (count++ >= ReasonLimit) break;
                capped.Append(rune.ToString());
            }
            var shown = Links.Shown(capped.ToString()).Text.Trim();
            if (shown.Length > 0) reason = shown;
        }

        string? claimed = null;
        if (values.TryGetValue("app", out var rawApp) && IsSafeAppClaim(rawApp))
            claimed = rawApp;

        return new AccessRequest(pane, minutes, reason, claimed);
    }

    static string UnescapeQuery(string text)
    {
        try { return Uri.UnescapeDataString(text.Replace('+', ' ')); }
        catch (UriFormatException) { return text; }
    }

    static bool IsSafeAppClaim(string text) =>
        text.Length is > 0 and <= 255
        && !text.Any(c => char.IsControl(c));

    /// <summary>
    /// The apps a process runs inside, nearest first: its own program, then each parent
    /// up to <paramref name="maxAncestors"/> steps. Skips Revoke itself.
    /// </summary>
    public static List<Client> AppsBehind(uint pid, IReadOnlyList<Proc> procs, uint selfPid, int maxAncestors = 16)
    {
        var result = new List<Client>();
        if (pid == 0 || pid == selfPid) return result;
        var byPid = procs.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.First());
        if (!byPid.TryGetValue(pid, out var current)) return result;

        for (var i = 0; i <= maxAncestors && current is not null; i++)
        {
            if (current.Pid != selfPid && current.Path is { } path
                && !Path.GetFileName(path).Equals("Revoke.exe", StringComparison.OrdinalIgnoreCase))
            {
                var client = current.Family is { } family ? Client.Package(family) : Client.FromPath(path);
                if (!result.Contains(client)) result.Add(client);
            }
            if (current.Parent == 0 || current.Parent == current.Pid) break;
            if (!byPid.TryGetValue(current.Parent, out var parent) || parent.Started > current.Started) break;
            current = parent;
        }
        return result;
    }

    /// <summary>Registers <c>revoke://</c> for this user so links can also open Revoke.</summary>
    public static void TryRegisterProtocol()
    {
        if (Environment.ProcessPath is not { } program
            || !Path.GetFileName(program).Equals("Revoke.exe", StringComparison.OrdinalIgnoreCase))
            return;
        try
        {
            using var root = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{Scheme}");
            root.SetValue(null, "URL:Revoke Protocol", RegistryValueKind.String);
            root.SetValue("URL Protocol", "", RegistryValueKind.String);
            using var command = root.CreateSubKey(@"shell\open\command");
            command.SetValue(null, $"\"{program}\" {RequestUrlFlag} \"%1\"", RegistryValueKind.String);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException) { }
    }
}
