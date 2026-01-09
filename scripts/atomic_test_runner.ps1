<# 
.SYNOPSIS
    Iron City IT - Atomic Red Team Test Runner
.DESCRIPTION
    Runs Atomic Red Team tests for detection validation (Purple Team)
.NOTES
    This script requires administrative privileges and explicit authorization
#>

param(
    [string]$TechniqueId = "T1059.001",
    [string]$TestGuids = "",
    [switch]$ListTests,
    [switch]$Cleanup,
    [string]$OutputDir = ".\results\atomic"
)

$ErrorActionPreference = "Stop"

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║  IRON CITY IT - ATOMIC RED TEAM TEST RUNNER               ║" -ForegroundColor Magenta
Write-Host "║  Purple Team Detection Validation                          ║" -ForegroundColor Magenta
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Some tests require administrative privileges"
}

# Install Invoke-AtomicRedTeam if not present
if (-not (Get-Module -ListAvailable -Name "Invoke-AtomicRedTeam")) {
    Write-Host "📥 Installing Invoke-AtomicRedTeam..." -ForegroundColor Cyan
    
    IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
    Install-AtomicRedTeam -getAtomics -Force
}

Import-Module Invoke-AtomicRedTeam

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$timestamp = Get-Date -Format "yyyy-MM-ddTHH-mm-ssZ"

if ($ListTests) {
    Write-Host "📋 Available tests for $TechniqueId :" -ForegroundColor Yellow
    Invoke-AtomicTest $TechniqueId -ShowDetailsBrief
    exit
}

Write-Host "🎯 Running Atomic Test: $TechniqueId" -ForegroundColor Yellow
Write-Host "⚠️  This is an AUTHORIZED security test" -ForegroundColor Red
Write-Host ""

# Run the test
$results = @{
    technique = $TechniqueId
    timestamp = $timestamp
    hostname = $env:COMPUTERNAME
    user = $env:USERNAME
    tests = @()
}

try {
    # Get test details
    $testDetails = Invoke-AtomicTest $TechniqueId -ShowDetails
    
    # Log test execution
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
    
    if ($TestGuids) {
        # Run specific test
        Invoke-AtomicTest $TechniqueId -TestGuids $TestGuids -GetPrereqs
        $output = Invoke-AtomicTest $TechniqueId -TestGuids $TestGuids
        
        $results.tests += @{
            test_guid = $TestGuids
            status = "executed"
            output = $output
        }
    }
    else {
        # Run all tests for technique (prerequisites only - safer)
        Write-Host "📍 Checking prerequisites..." -ForegroundColor Cyan
        Invoke-AtomicTest $TechniqueId -GetPrereqs
        
        # Log what would be executed
        $atomics = Get-AtomicTechnique -Path "$env:USERPROFILE\AtomicRedTeam\atomics" | Where-Object { $_.attack_technique -eq $TechniqueId }
        
        foreach ($test in $atomics.atomic_tests) {
            $results.tests += @{
                test_name = $test.name
                description = $test.description
                executor = $test.executor.name
                status = "logged"
            }
            Write-Host "  📍 Logged: $($test.name)" -ForegroundColor Green
        }
    }
    
    # Cleanup if requested
    if ($Cleanup) {
        Write-Host "🧹 Running cleanup..." -ForegroundColor Yellow
        Invoke-AtomicTest $TechniqueId -Cleanup
    }
}
catch {
    Write-Warning "Error during test execution: $_"
    $results.error = $_.ToString()
}

# Save results
$outputFile = Join-Path $OutputDir "$TechniqueId-$timestamp.json"
$results | ConvertTo-Json -Depth 10 | Out-File $outputFile -Encoding UTF8

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
Write-Host "✅ Results saved to: $outputFile" -ForegroundColor Green
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║  ATOMIC TEST COMPLETE                                      ║" -ForegroundColor Magenta
Write-Host "║  Review SIEM/Wazuh for detection validation               ║" -ForegroundColor Magenta
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
