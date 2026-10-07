namespace Revoke.Core;

public enum ClientKind
{
    /// <summary>A packaged (MSIX) app, by package family name: "Claude_pzs8sxrjxfjjc".</summary>
    Package,

    /// <summary>A desktop program, by lowercase path pattern: "c:\users\…\claude-code\*\claude.exe".</summary>
    Exe,
}

/// <summary>
/// An app as Revoke tracks it. Packaged apps (MSIX, which is how Claude and ChatGPT
/// install) are known by their package family name, which stays the same across
/// updates. Everything else is known by its path, with version and hash folders
/// replaced by <c>*</c> so a tool that updates itself into a new folder
/// ("claude-code\2.1.284\claude.exe") stays one client.
/// </summary>
public sealed record Client(ClientKind Kind, string Id) : IComparable<Client>
{
    public static Client Package(string family) => new(ClientKind.Package, family);

    /// <summary>The client a program at this path belongs to. Programs inside a
    /// package's install folder belong to the package.</summary>
    public static Client FromPath(string path) =>
        FamilyFromInstallPath(path) is { } family ? Package(family) : new(ClientKind.Exe, Pattern(path));

    /// <summary>How settings and the UI refer to the client.</summary>
    public string Key => (Kind == ClientKind.Package ? "pkg:" : "exe:") + Id;

    public string? Family => Kind == ClientKind.Package ? Id : null;

    public bool MatchesPath(string path) => FromPath(path) == this;

    public static Client? FromKey(string key) =>
        key.StartsWith("pkg:", StringComparison.Ordinal) ? Package(key[4..])
        : key.StartsWith("exe:", StringComparison.Ordinal) ? new(ClientKind.Exe, key[4..].ToLowerInvariant())
        : null;

    public int CompareTo(Client? other) => string.CompareOrdinal(Key, other?.Key);

    public override string ToString() => Key;

    /// <summary>
    /// The package family a file in "C:\Program Files\WindowsApps\&lt;full name&gt;\…"
    /// belongs to. A full name is Name_Version_Architecture_ResourceId_PublisherId,
    /// and the family is Name_PublisherId. Package names can't contain underscores.
    /// </summary>
    public static string? FamilyFromInstallPath(string path)
    {
        const string marker = @"\windowsapps\";
        var start = path.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (start < 0) return null;
        var folder = path[(start + marker.Length)..].Split('\\')[0];
        var parts = folder.Split('_');
        return parts.Length == 5 ? $"{parts[0]}_{parts[4]}" : null;
    }

    /// <summary>A path, lowercase, with folders that look like versions or hashes replaced by <c>*</c>.</summary>
    public static string Pattern(string path) =>
        string.Join('\\', path.ToLowerInvariant().Split('\\').Select(s => IsVariable(s) ? "*" : s));

    /// <summary>"2.1.284", "v1.4", "app-1.0.9", "9691020b546a15b2".</summary>
    static bool IsVariable(string segment)
    {
        var version = segment.StartsWith("app-") ? segment[4..] : segment.StartsWith('v') ? segment[1..] : segment;
        var first = version.Split('.', '-', '+')[0];
        var looksLikeVersion = version.Contains('.')
            && first.Length > 0 && first.All(char.IsAsciiDigit)
            && version.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '+');
        var looksLikeHash = segment.Length >= 12 && segment.All(char.IsAsciiHexDigit) && segment.Any(char.IsAsciiDigit);
        return looksLikeVersion || looksLikeHash;
    }

    /// <summary>The paths that exist now for a pattern, expanding each <c>*</c> to the folders there.</summary>
    public static List<string> Expand(string pattern)
    {
        var found = new List<string> { "" };
        var segments = pattern.Split('\\');
        for (var i = 0; i < segments.Length; i++)
        {
            var next = new List<string>();
            foreach (var path in found)
            {
                if (segments[i] == "*")
                {
                    try { next.AddRange(Directory.EnumerateFileSystemEntries(path + "\\")); }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
                }
                else
                {
                    next.Add(i == 0 ? segments[i] : $"{path}\\{segments[i]}");
                }
            }
            found = next;
        }
        return found.Where(File.Exists).ToList();
    }

    /// <summary>The developer a publisher name stands for, for grouping: "Anthropic, PBC"
    /// is "anthropic", "OpenAI OpCo, LLC" is "openai".</summary>
    public static string VendorKey(string publisher) =>
        publisher.Split(c => !char.IsLetterOrDigit(c)).FirstOrDefault(w => w.Length > 0)?.ToLowerInvariant() ?? "";

    /// <summary>The program in a command line: the quoted part, or everything up to ".exe".</summary>
    public static string ProgramInCommand(string command)
    {
        command = command.Trim();
        string program;
        if (command.StartsWith('"'))
        {
            var end = command.IndexOf('"', 1);
            program = end < 0 ? command[1..] : command[1..end];
        }
        else
        {
            var end = command.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            program = end < 0 ? command : command[..(end + 4)];
        }
        return Environment.ExpandEnvironmentVariables(program);
    }
}

static class StringSplitExtensions
{
    public static string[] Split(this string text, Func<char, bool> separator)
    {
        var parts = new List<string>();
        var start = 0;
        for (var i = 0; i <= text.Length; i++)
        {
            if (i == text.Length || separator(text[i]))
            {
                parts.Add(text[start..i]);
                start = i + 1;
            }
        }
        return [.. parts];
    }
}
