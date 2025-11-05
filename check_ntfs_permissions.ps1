<# 
.SYNOPSIS
  Findet aufgebrochene/abweichende NTFS-Rechte relativ zum Parent und zeigt die Unterschiede (Diffs) an.

.DESCRIPTION
  - Nutzt NTFSSecurity für gut lesbare Ausgabe (Get-NTFSAccess).
  - Vergleicht je Objekt (Child) dessen ACL mit der ACL des Parent:
      * Added:   explizite Einträge am Child, die der Parent nicht liefert
      * Removed: Einträge, die der Parent vererben würde, am Child aber fehlen
      * Changed: gleiche Identität & Typ (Allow/Deny), aber andere Rechte
  - Erkennt deaktivierte Vererbung (AreAccessRulesProtected).
  - Spezialfall: Vererbung deaktiviert, aber explizite ACEs am Child sind
    inhaltlich identisch zu den vom Parent vererbbaren ACEs -> **keine Abweichung**.
  - Thumbs.db wird vollständig ignoriert (kein Output, keine Warnungen).

.NOTES
  Voraussetzung: PowerShell 5+ und Modul "NTFSSecurity"
  Installation:  Install-Module NTFSSecurity
#>

# --- Modul laden ---
try {
    if (-not (Get-Module -ListAvailable -Name NTFSSecurity)) {
        Write-Host "Lade Modul NTFSSecurity ..." -ForegroundColor Yellow
        Import-Module NTFSSecurity -ErrorAction Stop
    } else {
        Import-Module NTFSSecurity -ErrorAction Stop
    }
} catch {
    Write-Error "NTFSSecurity konnte nicht geladen werden: $($_.Exception.Message)"
    return
}

# --- Hilfsfunktionen ---

function As-Array {
    param($InputObject)
    if ($null -eq $InputObject) { return @() }
    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        return @($InputObject)
    } else {
        return ,$InputObject
    }
}

function Test-SkipPath {
    param([Parameter(Mandatory)][string]$Path)
    try {
        return ([System.IO.Path]::GetFileName($Path) -ieq 'Thumbs.db')
    } catch { return $false }
}

function Get-AclInfo {
    param(
        [Parameter(Mandatory)][string]$Path
    )
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    $acl  = Get-Acl -LiteralPath $Path -ErrorAction Stop

    [PSCustomObject]@{
        Path                     = $item.FullName
        IsDirectory              = $item.PSIsContainer
        AreAccessRulesProtected  = $acl.AreAccessRulesProtected
        AccessRules              = As-Array $acl.Access
    }
}

function Normalize-AceKey {
    param(
        [System.Security.AccessControl.FileSystemAccessRule]$Ace
    )
    $principal = $Ace.IdentityReference.Value.ToLowerInvariant()
    $type      = $Ace.AccessControlType.ToString()   # Allow / Deny
    $rightsInt = [int]$Ace.FileSystemRights          # Bitflag
    "{0}|{1}|{2}" -f $principal, $type, $rightsInt
}

function Build-AceMap {
    param($Aces)
    $map = @{}
    foreach ($ace in (As-Array $Aces)) {
        if ($null -eq $ace) { continue }
        $key = Normalize-AceKey $ace
        if (-not $map.ContainsKey($key)) { $map[$key] = $ace }
    }
    $map
}

function Get-ParentInheritableAcesForChildType {
    param(
        $ParentAces,
        [bool]$ChildIsDirectory
    )
    $neededFlag = if ($ChildIsDirectory) {'ContainerInherit'} else {'ObjectInherit'}
    (As-Array $ParentAces) | Where-Object {
        $_.InheritanceFlags.ToString().Contains($neededFlag)
    }
}

function Compare-AclToParent {
    param(
        [Parameter(Mandatory)][string]$Path
    )

    # Thumbs.db still überspringen
    if (Test-SkipPath $Path) { return $null }

    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    } catch { return $null }

    $parentDir = Split-Path -Parent $item.FullName
    if (-not $parentDir -or (Test-SkipPath $parentDir)) { return $null }

    try {
        $childInfo  = Get-AclInfo -Path $item.FullName
        $parentInfo = Get-AclInfo -Path $parentDir
    } catch { return $null }

    # Vom Parent vererbbar (passend zum Child-Typ)
    $parentInheritable = Get-ParentInheritableAcesForChildType -ParentAces $parentInfo.AccessRules -ChildIsDirectory:$childInfo.IsDirectory

    # Child-ACEs
    $childAcesAll   = As-Array $childInfo.AccessRules
    $childInherited = $childAcesAll | Where-Object { $_.IsInherited }
    $childExplicit  = $childAcesAll | Where-Object { -not $_.IsInherited }

    # Maps
    $mapParent = Build-AceMap $parentInheritable
    $mapInh    = Build-AceMap $childInherited
    $mapExpl   = Build-AceMap $childExplicit

    # --- Diff-Logik ---
    # Added: explizite Child-ACEs, die der Parent nicht liefert (identische Rechte => NICHT added)
    $added = @()
    foreach ($k in $mapExpl.Keys) {
        if (-not $mapParent.ContainsKey($k)) {
            $added += $mapExpl[$k]
        }
    }

    # Removed: Parent würde etwas vererben, aber am Child ist weder ein geerbter
    #          noch ein identischer expliziter Eintrag vorhanden.
    $removed = @()
    foreach ($k in $mapParent.Keys) {
        if (-not ($mapInh.ContainsKey($k) -or $mapExpl.ContainsKey($k))) {
            $removed += $mapParent[$k]
        }
    }

    # Changed: gleicher Principal & Typ, aber andere Rechte (unabhängig von Vererbung)
    function PairKeyIdType([System.Security.AccessControl.FileSystemAccessRule]$ace) {
        "{0}|{1}" -f $ace.IdentityReference.Value.ToLowerInvariant(), $ace.AccessControlType.ToString()
    }

    $parentByIdType = @{}
    foreach ($p in (As-Array $parentInheritable)) {
        $k = PairKeyIdType $p
        if (-not $parentByIdType.ContainsKey($k)) { $parentByIdType[$k] = @{} }
        $parentByIdType[$k][[int]$p.FileSystemRights] = $p
    }

    $changed = @()
    foreach ($c in $childAcesAll) {
        $k = PairKeyIdType $c
        if ($parentByIdType.ContainsKey($k)) {
            $rightsInt   = [int]$c.FileSystemRights
            $matchExists = $parentByIdType[$k].ContainsKey($rightsInt)
            if (-not $matchExists) {
                # Als "changed" nur zählen, wenn es nicht ohnehin Added/Removed ist.
                $ckey = Normalize-AceKey $c
                if (-not $mapParent.ContainsKey($ckey)) {
                    $changed += $c
                }
            }
        }
    }

    [PSCustomObject]@{
        Path                    = $childInfo.Path
        IsDirectory             = $childInfo.IsDirectory
        AreAccessRulesProtected = $childInfo.AreAccessRulesProtected
        AddedExplicit           = As-Array $added
        RemovedInherited        = As-Array $removed
        ChangedCompared         = As-Array $changed
        ParentPath              = $parentInfo.Path
    }
}

function Show-NtfsRights {
    param(
        [Parameter(Mandatory)][string]$Path
    )
    if (Test-SkipPath $Path) { return }

    Write-Host ""
    Write-Host "=== Rechte für: $Path ===" -ForegroundColor Cyan
    try {
        Get-NTFSAccess -Path $Path |
            Select-Object Account,AccessControlType,FileSystemRights,IsInherited,InheritanceFlags,PropagationFlags |
            Format-Table -AutoSize
    } catch {
        Write-Warning "Get-NTFSAccess fehlgeschlagen, nutze Get-Acl-Fallback: $($_.Exception.Message)"
        try {
            (Get-Acl -LiteralPath $Path -ErrorAction Stop).Access |
                Select-Object IdentityReference,AccessControlType,FileSystemRights,IsInherited,InheritanceFlags,PropagationFlags |
                Format-Table -AutoSize
        } catch {
            # still schlucken, z. B. bei gelöschten/gesperrten Items
        }
    }
}

function Format-AceSummary {
    param([System.Security.AccessControl.FileSystemAccessRule]$Ace)
    "$($Ace.IdentityReference.Value) : $($Ace.AccessControlType) $($Ace.FileSystemRights) (Inherit=$($Ace.InheritanceFlags), Prop=$($Ace.PropagationFlags))"
}

# -------- Hauptablauf --------

$root = Read-Host "Bitte Root-Ordner angeben"
if (-not (Test-Path -LiteralPath $root)) {
    Write-Error "Pfad existiert nicht: $root"
    return
}

Write-Host ""
Write-Host "Wie sollen die Ergebnisse aufbereitet werden?" -ForegroundColor Yellow
Write-Host "[1] Alle Abweichungen (rekursiv: Ordner + Dateien, sortiert)"
Write-Host "[2] Nur Ordner-Berechtigungen betrachten"
$mode = Read-Host "Auswahl (1/2)"
if ($mode -notin @('1','2')) { $mode = '1' }

# Root-Rechte zuerst
Show-NtfsRights -Path $root

# Kandidatenliste (keine Pipe direkt hinter if/else)
if ($mode -eq '2') {
    $items = Get-ChildItem -LiteralPath $root -Recurse -Force -Directory -ErrorAction SilentlyContinue
} else {
    $items = Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

# Thumbs.db entfernen (still)
$items = $items | Where-Object { $_.Name -ne 'Thumbs.db' }
$items = $items | Sort-Object FullName

Write-Host ""
Write-Host "Analysiere Unterschiede relativ zum jeweiligen Parent ..." -ForegroundColor Yellow

foreach ($it in $items) {
    try {
        $diff = Compare-AclToParent -Path $it.FullName
        if ($null -eq $diff) { continue }

        $hasAdded   = ($diff.AddedExplicit    | Measure-Object).Count -gt 0
        $hasRemoved = ($diff.RemovedInherited | Measure-Object).Count -gt 0
        $hasChanged = ($diff.ChangedCompared  | Measure-Object).Count -gt 0
        $isProt     = $diff.AreAccessRulesProtected

        if ($hasAdded -or $hasRemoved -or $hasChanged -or $isProt) {
            Write-Host ""
            Write-Host ("---- {0} ----" -f $diff.Path) -ForegroundColor Green
            Write-Host ("Parent: {0}" -f $diff.ParentPath) -ForegroundColor DarkGray
            if ($isProt) {
                Write-Host "Vererbung: DEAKTIVIERT (AreAccessRulesProtected = True)" -ForegroundColor Magenta
            } else {
                Write-Host "Vererbung: Aktiv" -ForegroundColor DarkGray
            }

            # Absolute Rechte am Child
            Show-NtfsRights -Path $diff.Path

            # Diffs relativ zum Parent
            if ($hasAdded) {
                Write-Host " + Hinzugefügte (explizite) ACEs am Child gegenüber Parent:" -ForegroundColor Yellow
                $diff.AddedExplicit | ForEach-Object { "   + $(Format-AceSummary $_)" } | Write-Host
            }
            if ($hasRemoved) {
                Write-Host " - Fehlende (würden vom Parent vererbt), am Child jedoch nicht vorhanden (weder geerbt noch identisch explizit):" -ForegroundColor Yellow
                $diff.RemovedInherited | ForEach-Object { "   - $(Format-AceSummary $_)" } | Write-Host
            }
            if ($hasChanged) {
                Write-Host " ~ Geänderte ACEs am Child (gleiche Identität/Typ, andere Rechte als Parent):" -ForegroundColor Yellow
                $diff.ChangedCompared | ForEach-Object { "   ~ $(Format-AceSummary $_)" } | Write-Host
            }
        }
    } catch {
        if (-not (Test-SkipPath $it.FullName)) {
            Write-Warning "Fehler bei '$($it.FullName)': $($_.Exception.Message)"
        }
        # Bei Thumbs.db oder gesperrten Pfaden still weitermachen
    }
}

Write-Host ""
Write-Host "Fertig. Abweichungen wurden inklusive absoluter Rechte am Child und Differenzen zum Parent dargestellt." -ForegroundColor Cyan
