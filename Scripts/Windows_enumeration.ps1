<#
.SYNOPSIS
  Host/network/user/service/file permissions enumeration for Windows.
.USAGE
  Run in a standard PowerShell prompt:
    powershell -ExecutionPolicy Bypass -File .\enumerate_windows.ps1
  (Optional elevated adds extra info automatically.)
#>

# ---- Prep & Helpers ---------------------------------------------------------
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$Root = Join-Path -Path $PWD -ChildPath "enum_windows_$ts"
$null = New-Item -ItemType Directory -Path $Root -Force

$Text = Join-Path $Root 'summary.txt'
$Err  = Join-Path $Root 'errors.txt'
$Json = Join-Path $Root 'facts.json'

$Facts = [ordered]@{
  run_timestamp = (Get-Date).ToString("o")
  is_admin      = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  host          = $env:COMPUTERNAME
  user          = $env:USERNAME
  domain        = $env:USERDOMAIN
  os            = $null
  ip_addresses  = @()
  av_edr        = @()
  hotfixes      = @()
  listeners     = @()
  shares        = @()
  users         = @()
  groups        = @()
  scheduled     = @()
  services      = @()
  drivers       = @()
  software      = @()
}

Function Write-Log($msg) { $msg | Tee-Object -FilePath $Text -Append | Out-Null }
Function Try-Run($Label, [ScriptBlock]$Action) {
  Write-Log "=== $Label ==="
  try { & $Action | Tee-Object -FilePath $Text -Append | Out-Null }
  catch { "[!] $($Label): $($_.Exception.Message)" | Tee-Object -FilePath $Err -Append | Out-Null }
  Write-Log ""
}

# ---- System Info ------------------------------------------------------------
Try-Run "System / OS" {
  $os = Get-CimInstance Win32_OperatingSystem
  $cs = Get-CimInstance Win32_ComputerSystem
  $bios = Get-CimInstance Win32_BIOS
  $Facts.os = [ordered]@{
    caption   = $os.Caption
    version   = $os.Version
    build     = $os.BuildNumber
    arch      = (Get-CimInstance Win32_Processor | Select-Object -First 1).AddressWidth
    install   = $os.InstallDate
    lastboot  = $os.LastBootUpTime
    hostname  = $cs.Name
    manufacturer = $cs.Manufacturer
    model        = $cs.Model
    bios_version = $bios.SMBIOSBIOSVersion
  }
  $os, $cs, $bios | Format-List *
}

Try-Run "Uptime / Time / Locale" {
  systeminfo | Select-String "System Boot Time|System Locale|Input Locale|Time Zone"
}

Try-Run "Environment & PATH" { Get-ChildItem Env: | Sort-Object Name | Format-Table -Auto }

# ---- Network ----------------------------------------------------------------
Try-Run "IP Config" {
  ipconfig /all
  $Facts.ip_addresses = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {$_.IPAddress -notmatch '^169\.254\.'} |
    Select-Object -ExpandProperty IPAddress)
}

Try-Run "ARP / Routes / DNS" {
  arp -a
  route print
  Get-DnsClientServerAddress | Format-Table -Auto
}

Try-Run "Listening ports (TCP/UDP)" {
  $net = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Select-Object LocalAddress,LocalPort,OwningProcess,AppliedSetting
  $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
    Select-Object LocalAddress,LocalPort,OwningProcess
  $pmap = Get-Process | Select-Object Id,ProcessName
  $listeners = @()
  foreach ($n in $net) {
    $proc = ($pmap | Where-Object {$_.Id -eq $n.OwningProcess}).ProcessName
    $listeners += [ordered]@{proto="tcp";addr=$n.LocalAddress;port=$n.LocalPort;pid=$n.OwningProcess;proc=$proc}
  }
  foreach ($u in $udp) {
    $proc = ($pmap | Where-Object {$_.Id -eq $u.OwningProcess}).ProcessName
    $listeners += [ordered]@{proto="udp";addr=$u.LocalAddress;port=$u.LocalPort;pid=$u.OwningProcess;proc=$proc}
  }
  $Facts.listeners = $listeners
  $listeners | Format-Table -Auto
}

# ---- Accounts & Privs -------------------------------------------------------
Try-Run "Current Token / Groups" {
  whoami /all
}

Try-Run "Local Users & Groups" {
  # Ensure module is available on older systems
  Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue
  $Facts.users = @(Get-LocalUser | Select-Object Name,Enabled,LastLogon)
  $Facts.groups = @(Get-LocalGroup | ForEach-Object {
    [ordered]@{
      name   = $_.Name
      members = (Try { (Get-LocalGroupMember $_.Name).Name -join ", " } Catch { "" })
    }
  })
  Get-LocalUser | Format-Table Name,Enabled,LastLogon
  "`n-- Groups & Members --"
  foreach ($g in Get-LocalGroup) {
    "[$($g.Name)]"
    Try { (Get-LocalGroupMember $g.Name) | Format-Table Name, ObjectClass } Catch {}
    ""
  }
}

Try-Run "Domain (if joined)" {
  Try { (Get-ADDomain | Format-List *) } Catch { "Not a domain member or RSAT not present." }
}

# ---- Services, Drivers, Tasks -----------------------------------------------
Try-Run "Services (auto)" {
  $svc = Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq "Auto"} |
    Select-Object Name,DisplayName,State,StartMode,PathName
  $Facts.services = @($svc | ForEach-Object { $_ | Select-Object Name,State,PathName })
  $svc | Sort-Object Name | Format-Table -Auto
}

Try-Run "Drivers (non-Microsoft, running)" {
  $drv = Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq "Running" -and $_.PathName -and $_.Manufacturer -notmatch "Microsoft" } |
    Select-Object Name,State,PathName,Manufacturer
  $Facts.drivers = @($drv)
  $drv | Format-Table -Auto
}

Try-Run "Scheduled Tasks" {
  $tasks = Get-ScheduledTask | ForEach-Object {
    $def = $null
    try { $def = $_ | Get-ScheduledTaskInfo } catch {}
    [ordered]@{
      TaskName   = $_.TaskName
      State      = $_.State
      Author     = $_.Author
      LastRun    = if ($def) { $def.LastRunTime } else { $null }
      NextRun    = if ($def) { $def.NextRunTime } else { $null }
      Actions    = ($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join " | "
      Principal  = $_.Principal.UserId
      RunLevel   = $_.Principal.RunLevel
    }
  }
  $Facts.scheduled = $tasks
  $tasks | Sort-Object TaskName | Format-Table -Auto
}

# ---- Software / Patches / AV-EDR -------------------------------------------
Try-Run "Installed Software (x64/x86)" {
  $paths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
  )

  $swRaw = foreach ($p in $paths) {
    Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
      Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue
    }
  }

  $sw = $swRaw |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName -Unique

  $Facts.software = @($sw)
  $sw | Format-Table -Auto
}

Try-Run "Installed Hotfixes" {
  $hf = Get-HotFix | Sort-Object InstalledOn -Descending
  $Facts.hotfixes = @($hf | Select-Object HotFixID,InstalledOn)
  $hf | Format-Table -Auto
}

Try-Run "Security Products (AV/EDR)" {
  $sec = $null
  try { $sec = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct } catch {}
  if ($sec) {
    $Facts.av_edr = @($sec | Select-Object displayName,productState,pathToSignedProductExe)
    $sec | Format-Table displayName,productState
  } else {
    "No WMI SecurityCenter2 data (server SKUs often disable it)."
  }
}

# ---- Shares / Files / ACL quick-wins ----------------------------------------
Try-Run "Network Shares" {
  $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {$_.Name -ne "IPC$"}
  $Facts.shares = @($shares | Select-Object Name,Path,Description,CurrentUsers)
  $shares | Format-Table -Auto
}

Try-Run "Writable Directories (common)" {
  $paths = @("$env:ProgramFiles", "$env:ProgramFiles (x86)", "$env:PUBLIC", "C:\")
  foreach ($p in $paths) {
    "Checking: $p"
    try {
      # Use -Recurse only (no -Depth for best compatibility with Windows PowerShell)
      Get-ChildItem -Path $p -Directory -ErrorAction SilentlyContinue -Recurse |
        ForEach-Object {
          $acl = Get-Acl $_.FullName
          $w = $acl.Access | Where-Object {
            $_.FileSystemRights -match "Write|Modify|FullControl" -and
            $_.IdentityReference -match "$env:USERNAME|Everyone|Users|Authenticated Users"
          }
          if ($w) { "[Writable] $($_.FullName) :: $($w.IdentityReference -join ', ')" }
        }
    } catch {}
  }
}

# ---- Interesting Configs ----------------------------------------------------
Try-Run "Hosts / Firewall / Proxy" {
  "HOSTS file:"
  Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue
  ""
  "Firewall profiles:"
  Get-NetFirewallProfile | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction
  ""
  "Proxy:"
  netsh winhttp show proxy
}

# ---- Output JSON ------------------------------------------------------------
try {
  ($Facts | ConvertTo-Json -Depth 6) | Out-File -Encoding UTF8 $Json
} catch {
  "[!] JSON write error: $($_.Exception.Message)" | Tee-Object -FilePath $Err -Append | Out-Null
}

Write-Log "Done. Results in: $Root"
