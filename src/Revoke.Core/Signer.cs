using System.Security.Cryptography.X509Certificates;

namespace Revoke.Core;

/// <summary>
/// Who signed a program, for deciding which developer it's from. This reads the
/// organization out of the embedded Authenticode signature without checking the
/// signature is valid, which is fine for what it decides: whether Revoke watches a
/// program by default. A program that lies about being from Anthropic only gets
/// itself revoked.
/// </summary>
public static class Signer
{
    const string OrganizationOid = "2.5.4.10";

    /// <summary>The organization ("Anthropic, PBC") that signed the program at <paramref name="path"/>.</summary>
    public static string? Organization(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // The loader replacement doesn't read Authenticode signatures.
            using var signed = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            using var certificate = new X509Certificate2(signed);
            foreach (var rdn in certificate.SubjectName.EnumerateRelativeDistinguishedNames())
            {
                if (rdn.GetSingleElementType().Value == OrganizationOid
                    && rdn.GetSingleElementValue() is { Length: > 0 } organization)
                {
                    return organization;
                }
            }
            return null;
        }
        catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
