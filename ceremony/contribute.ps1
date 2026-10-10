<#
  PQ-Identity Groth16 phase-2 ceremony: make one contribution (Windows PowerShell 5.1 or 7).

  Run it like this (from the kit folder, in a PowerShell window):
    powershell -NoProfile -ExecutionPolicy Bypass -File .\contribute.ps1 `
        -InputZkey .\credential_auth_v4_0001.zkey -Name "Your Name" -OutputZkey .\credential_auth_v4_0002.zkey

  Optional:
    -R1cs <file> -Ptau <file>     verify the output afterwards (files come with the kit if the coordinator added them)
    -ExpectInputSha256 <hex>      stop unless the input file has the sha256 the coordinator published
    -ExtraEntropy                 also type some random text (hidden, never saved)

  What it does: checks Node.js, then runs contribute_core.mjs (snarkjs zkey contribute through the
  snarkjs library). Randomness comes from the OS generator and stays in memory; nothing secret is
  written to disk, to a log or to the command line. It prints your contribution hash.
  -ExecutionPolicy Bypass applies to this one PowerShell process only; it changes no setting.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)][string]$InputZkey,
  [Parameter(Mandatory = $true, Position = 1)][string]$Name,
  [Parameter(Mandatory = $true, Position = 2)][string]$OutputZkey,
  [string]$R1cs,
  [string]$Ptau,
  [string]$ExpectInputSha256,
  [switch]$ExtraEntropy,
  [switch]$NoReceipt
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$core = Join-Path $here 'contribute_core.mjs'

if (-not (Test-Path -LiteralPath $core)) {
  Write-Host "contribute_core.mjs is missing next to this script. Use the complete kit folder." -ForegroundColor Red
  exit 2
}
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
  Write-Host "Node.js 20 or newer is needed. Install the LTS version from https://nodejs.org and open a new PowerShell window." -ForegroundColor Red
  exit 2
}
$nodeMajor = [int]((& node -p "process.versions.node.split('.')[0]") | Out-String).Trim()
if ($nodeMajor -lt 20) {
  Write-Host "Node.js 20 or newer is needed (found major version $nodeMajor)." -ForegroundColor Red
  exit 2
}
if ($Name -match '["`$\\]') {
  Write-Host 'The name may not contain quotes, backticks, "$" or "\".' -ForegroundColor Red
  exit 2
}
if (-not (Test-Path -LiteralPath $InputZkey)) {
  Write-Host "Input zkey not found: $InputZkey" -ForegroundColor Red
  exit 2
}
if (Test-Path -LiteralPath $OutputZkey) {
  Write-Host "Output already exists (not overwritten): $OutputZkey" -ForegroundColor Red
  exit 2
}

$nodeArgs = @($core, '--in', $InputZkey, '--name', $Name, '--out', $OutputZkey)
if ($R1cs -or $Ptau) {
  if (-not ($R1cs -and $Ptau)) {
    Write-Host "Give both -R1cs and -Ptau, or neither." -ForegroundColor Red
    exit 2
  }
  $nodeArgs += @('--r1cs', $R1cs, '--ptau', $Ptau)
}
if ($ExpectInputSha256) { $nodeArgs += @('--expect-in-sha256', $ExpectInputSha256) }
if ($ExtraEntropy) { $nodeArgs += '--extra-entropy' }
if ($NoReceipt) { $nodeArgs += '--no-receipt' }

Write-Host "Starting the contribution (this takes from a few seconds to a few minutes)..."
& node @nodeArgs
$code = $LASTEXITCODE
if ($code -ne 0) {
  Write-Host "The contribution did NOT complete (exit code $code). Do not send any output file; tell the coordinator." -ForegroundColor Red
}
exit $code
