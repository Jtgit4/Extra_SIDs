Write-Output "`n"; Get-ADTrust -Filter * | ForEach-Object {
    $trust = $_
    $isVulnerable = $trust.ForestTransitive -eq $false -and $trust.IntraForest -eq $true -and $trust.SIDFilteringForestAware -eq $false -and $trust.SIDFilteringQuarantined -eq $false -and $trust.Direction -eq 'BiDirectional'
    if ($isVulnerable) {
        Write-Output "`nTrust: $($trust.Name) is potentially vulnerable to cross-domain extra SID's attack"
    } else {
        $notVulnerableReason = @()
        if ($trust.ForestTransitive -ne $false) { $notVulnerableReason += "ForestTransitive is $($trust.ForestTransitive)" }
        if ($trust.IntraForest -ne $true) { $notVulnerableReason += "IntraForest is $($trust.IntraForest)" }
        if ($trust.SIDFilteringForestAware -ne $false) { $notVulnerableReason += "SIDFilteringForestAware is $($trust.SIDFilteringForestAware)" }
        if ($trust.SIDFilteringQuarantined -ne $false) { $notVulnerableReason += "SIDFilteringQuarantined is $($trust.SIDFilteringQuarantined)" }
        if ($trust.Direction -ne 'BiDirectional') { $notVulnerableReason += "Direction is $($trust.Direction)" }
        $reasons = $notVulnerableReason -join ', '
        Write-Output "`nTrust: $($trust.Name) does not appear to be vulnerable to cross-domain extra SID's attack (Reason: $reasons)"
    }
}; Write-Output "`n"