using System.Text;

namespace Revoke.Core;

/// <summary>Reads one line from a pipe without accepting an unbounded request.</summary>
public static class BoundedLine
{
    public static async Task<string?> ReadAsync(StreamReader reader, int maxChars, CancellationToken token)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxChars);
        var text = new StringBuilder();
        var buffer = new char[1024];
        while (true)
        {
            // Leave room for CRLF after an exactly full line.
            var count = await reader.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, maxChars + 2 - text.Length)), token);
            if (count == 0)
            {
                var partial = text.ToString().TrimEnd('\r');
                return partial.Length > 0 && partial.Length <= maxChars ? partial : null;
            }
            var newline = Array.IndexOf(buffer, '\n', 0, count);
            var length = newline < 0 ? count : newline;
            if (text.Length + length > maxChars + 1) return null;
            text.Append(buffer, 0, length);
            if (newline >= 0)
            {
                var line = text.ToString().TrimEnd('\r');
                return line.Length <= maxChars ? line : null;
            }
            if (text.Length > maxChars && text[^1] != '\r') return null;
        }
    }
}
