namespace Revoke.Core;

/// <summary>
/// A record of everything Revoke does: each change, each automatic stop, and each link it
/// stood in for, with what the person answered. Kept in %LOCALAPPDATA%\Revoke\Revoke.log,
/// which never leaves the PC. Past a megabyte it starts again, keeping the last one as
/// Revoke.old.log.
/// </summary>
public static class Log
{
    const long MaxBytes = 1024 * 1024;
    static readonly object gate = new();

    public static string FilePath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Revoke", "Revoke.log");

    /// <summary>Adds a line. A log that can't be written never stops Revoke from working.</summary>
    public static void Write(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}  {text.ReplaceLineEndings(" ")}{Environment.NewLine}";
        lock (gate)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                var file = new FileInfo(FilePath);
                if (file.Exists && file.Length > MaxBytes)
                    File.Move(FilePath, Path.ChangeExtension(FilePath, ".old.log"), overwrite: true);
                // Links are answered in a Revoke started just for them, beside the one in
                // the tray, so both may be writing.
                using var stream = new FileStream(FilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                using var writer = new StreamWriter(stream);
                writer.Write(line);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
    }
}
