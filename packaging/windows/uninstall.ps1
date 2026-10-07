# Removes Revoke installed by install.ps1, with its admin helper, keeping your settings.
#
#   irm https://raw.githubusercontent.com/benjweaver/revoke-windows/main/packaging/windows/uninstall.ps1 | iex
#
# The removal itself lives in install.ps1, next to the install it undoes.
& ([scriptblock]::Create((Invoke-RestMethod 'https://raw.githubusercontent.com/benjweaver/revoke-windows/main/packaging/windows/install.ps1' -UseBasicParsing))) -Uninstall
