using Windows.Management.Deployment;

namespace Revoke.Core;

/// <param name="Apps">Application IDs, for launching: shell:AppsFolder\&lt;family&gt;!&lt;id&gt;.</param>
/// <param name="Executables">Executables the manifest declares, relative to the install folder.</param>
/// <param name="StartupTasks">Each startup task the manifest declares, and whether it's on by default.</param>
public sealed record Package(
    string Family,
    string FullName,
    string Name,
    string Publisher,
    string InstallPath,
    string? Logo,
    IReadOnlyList<string> Apps,
    IReadOnlyList<string> Executables,
    IReadOnlyList<(string TaskId, bool EnabledByDefault)> StartupTasks);

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
                    Safe(() => LogoPath(package.Logo)),
                    Attributes(manifest, "Application", "Id"),
                    Attributes(manifest, "Application", "Executable").Select(e => e.Replace('/', '\\')).ToList(),
                    StartupTasks(manifest)));
            }
            catch (Exception)
            {
                // A package being installed or removed right now; the next read gets it.
            }
        }
        return packages;
    }

    static string? Safe(Func<string?> read)
    {
        try { return read(); }
        catch (Exception) { return null; }
    }

    static string ReadManifest(string install)
    {
        try { return File.ReadAllText(Path.Combine(install, "AppxManifest.xml")); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return ""; }
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
}
