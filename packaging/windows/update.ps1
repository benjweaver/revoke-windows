# Updates Revoke installed by install.ps1 to the latest release.
#
#   irm https://raw.githubusercontent.com/benjweaver/revoke-windows/main/packaging/windows/update.ps1 | iex
#
# The update itself lives in install.ps1, next to the install it repeats.
& ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/benjweaver/revoke-windows/main/packaging/windows/install.ps1' -UseBasicParsing))) -Update
