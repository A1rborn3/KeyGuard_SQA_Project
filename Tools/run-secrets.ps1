#command to run this script:
#Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#.\run-secrets.ps1
try {
	$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
} catch {
	$scriptDir = Get-Location
}

$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
#change path if need testing on different location
$secretsPath = Join-Path $repoRoot "KeyGuard.test\TestingFiles\Secrets.log"

if (-not (Test-Path $secretsPath)) {
	Write-Error "Secrets.log not found at: $secretsPath"
	exit 1
}

Write-Host "Scanning file: $secretsPath" -ForegroundColor Cyan

$projectFile = Join-Path $repoRoot "KeyGuard_SQAProject\KeyGuard_SQAProject.csproj"
if (-not (Test-Path $projectFile)) {
	Write-Error "Project file not found at: $projectFile"
	exit 2
}

# Run the scanner project with the secrets file as argument
dotnet run --project $projectFile -- $secretsPath
