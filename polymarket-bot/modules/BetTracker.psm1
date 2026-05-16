# BetTracker.psm1
# CSV-backed bet ledger + balance state + projection toward $1000 goal.

Set-StrictMode -Version Latest

function Get-LedgerPath {
    param([string] $DataDir)
    return Join-Path $DataDir 'bets.csv'
}

function Get-StatePath {
    param([string] $DataDir)
    return Join-Path $DataDir 'state.json'
}

function Initialize-Tracker {
    param(
        [Parameter(Mandatory)] [string] $DataDir,
        [double] $StartingBalance = 5.0,
        [double] $GoalBalance     = 1000.0
    )
    if (-not (Test-Path $DataDir)) {
        New-Item -ItemType Directory -Path $DataDir | Out-Null
    }
    $ledger = Get-LedgerPath -DataDir $DataDir
    if (-not (Test-Path $ledger)) {
        'Timestamp,Symbol,Direction,Stake,EntryPrice,ExitPrice,Result,Payout,PnL,BalanceAfter,Confidence,Notes' |
            Out-File -FilePath $ledger -Encoding utf8
    }
    $state = Get-StatePath -DataDir $DataDir
    if (-not (Test-Path $state)) {
        @{
            StartingBalance = $StartingBalance
            CurrentBalance  = $StartingBalance
            Goal            = $GoalBalance
            StartedAt       = (Get-Date).ToUniversalTime().ToString('o')
            TotalBets       = 0
            Wins            = 0
            Losses          = 0
        } | ConvertTo-Json -Depth 4 | Out-File -FilePath $state -Encoding utf8
    }
}

function Get-TrackerState {
    param([Parameter(Mandatory)] [string] $DataDir)
    $p = Get-StatePath -DataDir $DataDir
    return Get-Content $p -Raw | ConvertFrom-Json
}

function Save-TrackerState {
    param(
        [Parameter(Mandatory)] [string] $DataDir,
        [Parameter(Mandatory)] [object] $State
    )
    $p = Get-StatePath -DataDir $DataDir
    $State | ConvertTo-Json -Depth 4 | Out-File -FilePath $p -Encoding utf8
}

function Add-PendingBet {
    <#
    .SYNOPSIS
        Append a new (open) bet to the ledger. Result/PnL filled in later by Update-BetResult.
    #>
    param(
        [Parameter(Mandatory)] [string] $DataDir,
        [Parameter(Mandatory)] [string] $Symbol,
        [Parameter(Mandatory)] [ValidateSet('UP','DOWN')] [string] $Direction,
        [Parameter(Mandatory)] [double] $Stake,
        [Parameter(Mandatory)] [double] $EntryPrice,
        [Parameter(Mandatory)] [double] $Confidence,
        [string] $Notes = ''
    )
    $ledger = Get-LedgerPath -DataDir $DataDir
    $row = [pscustomobject]@{
        Timestamp    = (Get-Date).ToUniversalTime().ToString('o')
        Symbol       = $Symbol
        Direction    = $Direction
        Stake        = $Stake
        EntryPrice   = $EntryPrice
        ExitPrice    = ''
        Result       = 'OPEN'
        Payout       = ''
        PnL          = ''
        BalanceAfter = ''
        Confidence   = $Confidence
        Notes        = $Notes
    }
    $line = '{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},"{11}"' -f `
        $row.Timestamp, $row.Symbol, $row.Direction, $row.Stake, $row.EntryPrice,
        $row.ExitPrice, $row.Result, $row.Payout, $row.PnL, $row.BalanceAfter,
        $row.Confidence, ($row.Notes -replace '"','""')
    Add-Content -Path $ledger -Value $line -Encoding utf8
}

function Update-BetResult {
    <#
    .SYNOPSIS
        Settle the most recent OPEN bet (or all OPEN bets matching symbol).
        Polymarket binary market: stake of $S buys shares for $P each (P<1 = implied prob).
        For simplicity we treat odds as 1:1 (b=1) by default — override via -PayoutMultiplier.
    #>
    param(
        [Parameter(Mandatory)] [string] $DataDir,
        [Parameter(Mandatory)] [double] $ExitPrice,
        [double] $PayoutMultiplier = 1.0,
        [string] $SymbolFilter = $null
    )
    $ledger = Get-LedgerPath -DataDir $DataDir
    $rows = Import-Csv -Path $ledger
    $state = Get-TrackerState -DataDir $DataDir
    $updated = $false
    for ($i = $rows.Count - 1; $i -ge 0; $i--) {
        if ($rows[$i].Result -ne 'OPEN') { continue }
        if ($SymbolFilter -and $rows[$i].Symbol -ne $SymbolFilter) { continue }

        $entry = [double]$rows[$i].EntryPrice
        $stake = [double]$rows[$i].Stake
        $isWin = $false
        if ($rows[$i].Direction -eq 'UP'   -and $ExitPrice -gt $entry) { $isWin = $true }
        if ($rows[$i].Direction -eq 'DOWN' -and $ExitPrice -lt $entry) { $isWin = $true }

        if ($isWin) {
            $payout = $stake * (1 + $PayoutMultiplier)  # return of stake + profit
            $pnl    = $stake * $PayoutMultiplier
            $rows[$i].Result = 'WIN'
            $state.Wins = [int]$state.Wins + 1
        } else {
            $payout = 0
            $pnl    = -$stake
            $rows[$i].Result = 'LOSS'
            $state.Losses = [int]$state.Losses + 1
        }
        $state.CurrentBalance = [double]$state.CurrentBalance + $pnl
        $state.TotalBets = [int]$state.TotalBets + 1

        $rows[$i].ExitPrice    = $ExitPrice
        $rows[$i].Payout       = $payout
        $rows[$i].PnL          = $pnl
        $rows[$i].BalanceAfter = [Math]::Round([double]$state.CurrentBalance, 4)
        $updated = $true
        break  # settle one at a time
    }
    if ($updated) {
        $rows | Export-Csv -Path $ledger -NoTypeInformation -Encoding utf8
        Save-TrackerState -DataDir $DataDir -State $state
    }
    return $state
}

function Get-Projection {
    <#
    .SYNOPSIS
        Project days remaining to reach goal given observed win rate and bet cadence.
    #>
    param(
        [Parameter(Mandatory)] [string] $DataDir,
        [int]    $BetsPerDay        = 4,
        [double] $RiskPerBet        = 0.10,
        [double] $PayoutMultiplier  = 1.0
    )
    $state = Get-TrackerState -DataDir $DataDir
    $bal   = [double]$state.CurrentBalance
    $goal  = [double]$state.Goal
    $total = [int]$state.TotalBets
    $wins  = [int]$state.Wins

    if ($total -lt 5) {
        $winRate = 0.55  # assume baseline edge for the projection
    } else {
        $winRate = $wins / [double]$total
    }

    # Expected value per bet (fractional of balance)
    $ev = ($winRate * $PayoutMultiplier) - ((1 - $winRate) * 1.0)
    $expectedGrowthPerBet = $RiskPerBet * $ev
    $betsNeeded = [double]::PositiveInfinity
    if ($expectedGrowthPerBet -gt 0 -and $bal -gt 0) {
        $betsNeeded = [Math]::Log($goal / $bal) / [Math]::Log(1 + $expectedGrowthPerBet)
    }
    $daysNeeded = if ($betsNeeded -eq [double]::PositiveInfinity) { $null } `
                  else { [Math]::Ceiling($betsNeeded / $BetsPerDay) }

    return [pscustomobject]@{
        CurrentBalance        = [Math]::Round($bal, 4)
        Goal                  = $goal
        WinRate               = [Math]::Round($winRate, 4)
        TotalBets             = $total
        EVPerBet              = [Math]::Round($ev, 4)
        ExpectedGrowthPerBet  = [Math]::Round($expectedGrowthPerBet, 4)
        BetsNeededToGoal      = if ($betsNeeded -eq [double]::PositiveInfinity) { $null } else { [Math]::Ceiling($betsNeeded) }
        DaysToGoalEstimate    = $daysNeeded
        Note                  = if ($ev -le 0) { 'Negative EV — strategy unprofitable at current win rate.' } else { 'Projection assumes constant edge and fractional-Kelly sizing.' }
    }
}

Export-ModuleMember -Function Initialize-Tracker, Get-TrackerState, Save-TrackerState, Add-PendingBet, Update-BetResult, Get-Projection
