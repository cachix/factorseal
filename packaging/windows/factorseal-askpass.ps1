# Factorseal askpass helper for Windows.
#
# The logon task starts the vault with no console, so the vault runs this
# helper to obtain the vault's nested factor and reads it from standard output.
# The secret crosses a pipe and is never written to disk.
[CmdletBinding()]
param([string]$Label = 'Factorseal password:')

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Factorseal'
$form.FormBorderStyle = 'FixedDialog'
$form.StartPosition = 'CenterScreen'
$form.TopMost = $true
$form.MinimizeBox = $false
$form.MaximizeBox = $false
$form.ClientSize = New-Object System.Drawing.Size(360, 130)

$prompt = New-Object System.Windows.Forms.Label
$prompt.Text = $Label
$prompt.SetBounds(12, 15, 336, 20)
$form.Controls.Add($prompt)

$input = New-Object System.Windows.Forms.TextBox
$input.UseSystemPasswordChar = $true
$input.SetBounds(12, 40, 336, 24)
$form.Controls.Add($input)

$ok = New-Object System.Windows.Forms.Button
$ok.Text = 'Unseal'
$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
$ok.SetBounds(192, 80, 75, 26)
$form.Controls.Add($ok)
$form.AcceptButton = $ok

$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = 'Cancel'
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$cancel.SetBounds(273, 80, 75, 26)
$form.Controls.Add($cancel)
$form.CancelButton = $cancel

$form.Add_Shown({ $input.Focus() })
$result = $form.ShowDialog()
if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
    exit 1
}

[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::Out.Write($input.Text)
exit 0
