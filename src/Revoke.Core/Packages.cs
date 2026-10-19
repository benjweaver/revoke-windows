using Windows.Management.Deployment;

namespace Revoke.Core;

/// <summary>An app's logo: <paramref name="Path"/> for dark backgrounds, or any background
/// when there's only one, and <paramref name="OnLight"/> drawn for light ones, when the
/// package has it, as the taskbar uses in light mode.</summary>
public sealed record AppLogo(string Path, string? OnLight = null)
{
    public string For(bool lightBackground) => lightBackground ? OnLight ?? Path : Path;
}

/// <param name="Apps">Application IDs, for launching: shell:AppsFolder\&lt;family&gt;!&lt;id&gt;.</param>
/// <param name="Executables">Executables the manifest declares, relative to the install folder.</param>
/// <param name="StartupTasks">Each startup task the manifest declares, and whether it's on by default.</param>
/// <param name="Protocols">Link schemes the app opens: "claude".</param>
/// <param name="FileTypes">File types the app opens: ".skill".</param>
public sealed record Package(
    string Family,
    string FullName,
    string Name,
    string Publisher,
    string InstallPath,
    AppLogo? Logo,
    IReadOnlyList<string> Apps,
    IReadOnlyList<string> Executables,
    IReadOnlyList<(string TaskId, bool EnabledByDefault)> StartupTasks,
    IReadOnlyList<string> Protocols,
    IReadOnlyList<string> FileTypes);

/// <summary>Installed packaged (MSIX) apps, from Windows' package manager and their manifests.</summary>
public static class Packages
{
    /// <summary>Every app package installed for this user, frameworks and resource packs left out.</summary>
    public static List<Package> Installed()
    {
        var packages = new List<Package>();
        IEnumerable<Windows.ApplicationModel.Package> found;
        try
        {
            // An empty SID means the current user, which needs no admin rights.
            found = new PackageManager().FindPackagesForUser(string.Empty);
        }
        catch (Exception)
        {
            return packages;
        }
        foreach (var package in found)
        {
            try
            {
                if (package.IsFramework || package.IsResourcePackage) continue;
                var install = package.InstalledPath;
                var manifest = ReadManifest(install);
                packages.Add(new Package(
                    package.Id.FamilyName,
                    package.Id.FullName,
                    Safe(() => package.DisplayName) ?? package.Id.Name,
                    Safe(() => package.PublisherDisplayName) ?? "",
                    install,
                    Safe(() => Logo(install, manifest, package.Logo)),
                    Attributes(manifest, "Application", "Id"),
                    Attributes(manifest, "Application", "Executable").Select(e => e.Replace('/', '\\')).ToList(),
                    StartupTasks(manifest),
                    Attributes(manifest, "Protocol", "Name").Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                    Texts(manifest, "FileType").Select(t => t.Trim().ToLowerInvariant()).Distinct().ToList()));
            }
            catch (Exception)
            {
                // A package being installed or removed right now; the next read gets it.
            }
        }
        return packages;
    }

    static T? Safe<T>(Func<T?> read) where T : class
    {
        try { return read(); }
        catch (Exception) { return null; }
    }

    static string ReadManifest(string install)
    {
        try { return File.ReadAllText(Path.Combine(install, "AppxManifest.xml")); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return ""; }
    }

    /// <summary>
    /// The logo the taskbar shows: the app's Square44x44Logo in its unplated forms, one for
    /// dark backgrounds and one ("lightunplated") for light ones. Without those, the Store
    /// logo, which is drawn for the app's colored tile and can vanish on a card: ChatGPT's
    /// is white, on a blue tile.
    /// </summary>
    static AppLogo? Logo(string install, string manifest, Uri? storeLogo)
    {
        if (Attributes(manifest, "VisualElements", "Square44x44Logo").FirstOrDefault() is { } square
            && Path.GetDirectoryName(Path.Combine(install, square.Replace('/', '\\'))) is { } folder
            && Directory.Exists(folder))
        {
            var names = Directory.EnumerateFiles(folder).Select(Path.GetFileName).OfType<string>().ToList();
            var stem = Path.GetFileNameWithoutExtension(square);
            if (Unplated(names, stem, "unplated") is { } dark)
            {
                var light = Unplated(names, stem, "lightunplated");
                return new AppLogo(Path.Combine(folder, dark), light is null ? null : Path.Combine(folder, light));
            }
        }
        return LogoPath(storeLogo) is { } path ? new AppLogo(path) : null;
    }

    /// <summary>The "&lt;stem&gt;.targetsize-48_altform-&lt;form&gt;.png" file among
    /// <paramref name="names"/>: the smallest size of at least 48 pixels, which the panel
    /// draws at 150% and up, or else the biggest there is.</summary>
    internal static string? Unplated(IEnumerable<string> names, string stem, string form)
    {
        var prefix = stem + ".targetsize-";
        var suffix = "_altform-" + form + ".png";
        string? best = null;
        var bestSize = 0;
        foreach (var name in names)
        {
            if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                || !name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
                || !int.TryParse(name.AsSpan(prefix.Length, name.Length - prefix.Length - suffix.Length), out var size))
            {
                continue;
            }
            var better = best is null
                || (size >= 48 ? bestSize < 48 || size < bestSize : bestSize < 48 && size > bestSize);
            if (better) (best, bestSize) = (name, size);
        }
        return best;
    }

    /// <summary>The logo file. Packages name logos by scale ("StoreLogo.scale-100.png"),
    /// and the URI may name the unscaled file.</summary>
    static string? LogoPath(Uri? uri)
    {
        if (uri is null || !uri.IsFile) return null;
        var path = uri.LocalPath;
        if (File.Exists(path)) return path;
        var folder = Path.GetDirectoryName(path);
        if (folder is null || !Directory.Exists(folder)) return null;
        var stem = Path.GetFileNameWithoutExtension(path) + ".";
        // The biggest scale looks best drawn small.
        return Directory.EnumerateFiles(folder, stem + "*.png")
            .Where(f => !f.Contains("contrast-", StringComparison.OrdinalIgnoreCase))
            .Order(StringComparer.OrdinalIgnoreCase)
            .LastOrDefault();
    }

    /// <summary>Values of <paramref name="attribute"/> on every &lt;element&gt; or &lt;prefix:element&gt;
    /// tag. The manifest is machine-written XML, so a tag-and-attribute scan is enough.</summary>
    internal static List<string> Attributes(string xml, string element, string attribute) =>
        Tags(xml, element).Select(tag => AttributeIn(tag, attribute)).OfType<string>().ToList();

    internal static IEnumerable<string> Tags(string xml, string element)
    {
        foreach (var chunk in xml.Split('<'))
        {
            var end = chunk.IndexOfAny([' ', '\t', '\r', '\n', '>', '/']);
            var name = end < 0 ? chunk : chunk[..end];
            if (name.Split(':')[^1] == element) yield return chunk.Split('>')[0];
        }
    }

    /// <summary>The text inside every &lt;element&gt; or &lt;prefix:element&gt;: "&lt;uap:FileType&gt;.csv&lt;/uap:FileType&gt;".</summary>
    internal static List<string> Texts(string xml, string element) =>
        xml.Split('<')
            .Where(chunk => chunk.Contains('>') && chunk[..chunk.IndexOfAny([' ', '>', '/'])].Split(':')[^1] == element)
            .Select(chunk => chunk[(chunk.IndexOf('>') + 1)..].Trim())
            .Where(text => text.Length > 0)
            .ToList();

    static string? AttributeIn(string tag, string attribute)
    {
        var needle = $" {attribute}=\"";
        var start = tag.IndexOf(needle, StringComparison.Ordinal);
        if (start < 0) return null;
        start += needle.Length;
        var end = tag.IndexOf('"', start);
        return end < 0 ? null : tag[start..end];
    }

    internal static List<(string, bool)> StartupTasks(string manifest) =>
        Tags(manifest, "StartupTask")
            .Select(tag => (Id: AttributeIn(tag, "TaskId"), Enabled: AttributeIn(tag, "Enabled") == "true"))
            .Where(t => t.Id is not null)
            .Select(t => (t.Id!, t.Enabled))
            .ToList();

    /// <summary>The full names, which include the version, of the packages <see cref="Installed"/>
    /// reads. Much quicker than reading them, which goes through every app's resources for its
    /// name and logo, so it tells when one was installed, updated, or removed.</summary>
    public static HashSet<string> FullNames()
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            foreach (var package in new PackageManager().FindPackagesForUser(string.Empty))
            {
                try
                {
                    if (!package.IsFramework && !package.IsResourcePackage) names.Add(package.Id.FullName);
                }
                catch (Exception)
                {
                    // Being installed or removed right now; the next look gets it.
                }
            }
        }
        catch (Exception)
        {
            // As Installed() finds nothing too.
        }
        return names;
    }
}
