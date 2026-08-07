$ErrorActionPreference = 'Stop'

function ConvertTo-ConfigHashtable {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $hash = @{}
        foreach ($key in $InputObject.Keys) {
            $hash[$key] = ConvertTo-ConfigHashtable -InputObject $InputObject[$key]
        }
        return $hash
    }

    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $hash = @{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $hash[$prop.Name] = ConvertTo-ConfigHashtable -InputObject $prop.Value
        }
        return $hash
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $list = @()
        foreach ($item in $InputObject) {
            $list += , (ConvertTo-ConfigHashtable -InputObject $item)
        }
        return $list
    }

    return $InputObject
}

try {
    $configDir = "C:\Program Files\ClaudeCode"
    $configFile = Join-Path $configDir "managed-settings.json"

    New-Item -ItemType Directory -Path $configDir -Force | Out-Null

    $backupFile = $null

    if (Test-Path $configFile) {
        $timestamp = Get-Date -Format "yyyyMMddHHmmss"
        $backupFile = "$configFile.bak.$timestamp"
        Copy-Item -Path $configFile -Destination $backupFile -Force
        Write-Output "Backup created: $backupFile"
    }

    if (Test-Path $configFile) {
        $content = Get-Content $configFile -Raw

        if ([string]::IsNullOrWhiteSpace($content)) {
            $config = @{}
        }
        else {
            $config = ConvertTo-ConfigHashtable -InputObject (
                ConvertFrom-Json -InputObject $content -ErrorAction Stop
            )
        }
    }
    else {
        $config = @{}
    }

    if (-not $config.ContainsKey("extraKnownMarketplaces")) {
        $config["extraKnownMarketplaces"] = @{}
    }

    if (-not $config.ContainsKey("enabledPlugins")) {
        $config["enabledPlugins"] = @{}
    }

    foreach ($key in @($config["extraKnownMarketplaces"].Keys)) {
        if ($key -like "cx-devassist-marketplace*" -and $key -ne "cx-devassist-marketplace") {
            $config["extraKnownMarketplaces"].Remove($key)
        }
    }

    $config["extraKnownMarketplaces"]["cx-devassist-marketplace"] = @{
        source = @{
            source = "github"
            repo   = "Checkmarx/cx-agentic-ai"
        }
    }

    $config["enabledPlugins"]["cx-devassist@cx-devassist-marketplace"] = $true

    $json = $config | ConvertTo-Json -Depth 10

    [System.IO.File]::WriteAllText(
        $configFile,
        $json,
        (New-Object System.Text.UTF8Encoding($false))
    )

    Write-Output "SUCCESS: managed-settings.json updated successfully."

    if ($backupFile) {
        Write-Output "Backup saved at: $backupFile"
    }

    exit 0
}
catch {
    Write-Output "FAILED: $($_.Exception.Message)"
    exit 1
}