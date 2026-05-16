<#
.SYNOPSIS
    Polymarket BTC/ETH directional auto-predictor.

.DESCRIPTION
    Runs continuously and emits a directional prediction (UP/DOWN/NO_TRADE) at every
    scan interval (default: top of every hour, aligned to 4H candle close).
    Logs each prediction to data/predictions.csv. When -AutoBet is supplied AND
    confidence >= threshold AND a current OPEN bet doesn't exist, opens a paper bet
    with Kelly-sized stake and writes it to data/bets.csv. Settles the previous
    bet (if any) at start of each cycle using current spot price.

    THIS BOT DOES NOT PLACE REAL POLYMARKET TRADES. It produces signals + paper-trade
    ledger for you to mirror manually on polymarket.com.

.PARAMETER Once
    Run a single scan and exit (useful for cron/Task Scheduler).

.PARAMETER AutoBet
    Automatically open paper bets when confidence threshold is met.

.PARAMETER ConfigPath
    Path to config.json. Defaults to ./config.json next to this script.

.EXAMPLE
    pwsh ./Start-PolymarketBot.ps1 -Once
    pwsh ./Start-PolymarketBot.ps1 -AutoBet
#>
[CmdletBinding()]
param(
    [switch] $Once,
    [switch] $AutoBet,
    [string] $ConfigPath = (Join-Path $PSScriptRoot 'config.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'modules/MarketData.psm1')  -Force
Import-Module (Join-Path $PSScriptRoot 'modules/Indicators.psm1')  -Force
Import-Module (Join-Path $PSScriptRoot 'modules/Predictor.psm1')   -Force
Import-Module (Join-Path $PSScriptRoot 'modules/BetTracker.psm1')  -Force

function Write-Log {
    param(
        [string] $Message,
        [ValidateSet('INFO','WARN','ERROR','SIGNAL','BET','SETTLE')] [string] $Level = 'INFO'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'INFO'   { 'Gray' }
        'WARN'   { 'Yellow' }
        'ERROR'  { 'Red' }
        'SIGNAL' { 'Cyan' }
        'BET'    { 'Magenta' }
        'SETTLE' { 'Green' }
    }
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
    if ($script:LogFile) {
        Add-Content -Path $script:LogFile -Value "[$ts] [$Level] $Message" -Encoding utf8
    }
}

function Show-Banner {
    param([object] $Config, [object] $State)
    Write-Host ''
    Write-Host '================================================================' -ForegroundColor DarkCyan
    Write-Host '   POLYMARKET BTC/ETH AUTO-PREDICTOR  ($5 -> $1000 challenge)'  -ForegroundColor White
    Write-Host '================================================================' -ForegroundColor DarkCyan
    Write-Host ('   Balance : ${0:N4}   Goal: ${1:N0}   Bets: {2} ({3}W / {4}L)' -f `
        [double]$State.CurrentBalance, [double]$State.Goal, [int]$State.TotalBets, [int]$State.Wins, [int]$State.Losses) -ForegroundColor White
    Write-Host ('   Symbols : {0}   Min confidence: {1}   Scan: {2}m' -f `
        ($Config.symbols -join ', '), $Config.min_confidence, $Config.scan_interval_minutes) -ForegroundColor White
    Write-Host '================================================================' -ForegroundColor DarkCyan
    Write-Host ''
}

function Format-Prediction {
    param([object] $P)
    $arrow = switch ($P.Direction) {
        'UP'   { 'UP   /\' }
        'DOWN' { 'DOWN \/' }
        default { '-----' }
    }
    $line1 = ('{0,-9} | Price: `${1,-10:N2} | Signal: {2,-8} | Score: {3,5:N1}  Conf: {4,5:N1}%  pWin: {5:P1}' -f `
        $P.Symbol, [double]$P.Price, $arrow, [double]$P.Composite, [double]$P.Confidence, [double]$P.ProbWin)
    $line2 = ('          | 1D: {0,5:N1}   4H: {1,5:N1}   1H: {2,5:N1}   ATR4H: {3:N2}%   Funding: {4:P3}' -f `
        [double]$P.Score1D, [double]$P.Score4H, [double]$P.Score1H,
        $(if ($P.ATRPct4H) { [double]$P.ATRPct4H } else { 0 }),
        $(if (-not [double]::IsNaN([double]$P.FundingRate)) { [double]$P.FundingRate } else { 0 }))
    return @($line1, $line2)
}

function Save-Prediction {
    param(
        [Parameter(Mandatory)] [string] $DataDir,
        [Parameter(Mandatory)] [object] $P
    )
    $f = Join-Path $DataDir 'predictions.csv'
    if (-not (Test-Path $f)) {
        'Timestamp,Symbol,Price,Direction,Composite,Confidence,ProbWin,Score1D,Score4H,Score1H,RSI4H,ATRPct4H,FundingRate' |
            Out-File -FilePath $f -Encoding utf8
    }
    $line = '{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12}' -f `
        $P.Timestamp.ToString('o'), $P.Symbol, $P.Price, $P.Direction,
        $P.Composite, $P.Confidence, $P.ProbWin,
        $P.Score1D, $P.Score4H, $P.Score1H,
        $(if ($P.RSI4H) { $P.RSI4H } else { '' }),
        $(if ($P.ATRPct4H) { $P.ATRPct4H } else { '' }),
        $P.FundingRate
    Add-Content -Path $f -Value $line -Encoding utf8
}

function Invoke-OneCycle {
    param(
        [Parameter(Mandatory)] [object] $Config,
        [switch] $AutoBet
    )

    $dataDir = Join-Path $PSScriptRoot $Config.data_dir

    # 1) Settle any open bets at current price (auto-settle on each cycle)
    if ($Config.auto_settle) {
        $ledger = Join-Path $dataDir 'bets.csv'
        if (Test-Path $ledger) {
            $rows = Import-Csv $ledger
            $openBets = $rows | Where-Object { $_.Result -eq 'OPEN' }
            foreach ($b in $openBets) {
                # Polymarket bets typically expire at fixed times; here we settle if
                # the candle representing the bet expiry (entry + 4H) has closed.
                $entryTs = [datetime]::Parse($b.Timestamp).ToUniversalTime()
                $expiry  = $entryTs.AddHours(4)
                if ((Get-Date).ToUniversalTime() -ge $expiry) {
                    try {
                        $exit = Get-CurrentPrice -Symbol $b.Symbol
                        $st = Update-BetResult -DataDir $dataDir -ExitPrice $exit `
                                -PayoutMultiplier $Config.polymarket_payout_multiplier -SymbolFilter $b.Symbol
                        Write-Log ('Settled {0} bet (entry {1}) -> exit ${2:N2}, balance now ${3:N4}' -f `
                            $b.Symbol, $b.EntryPrice, $exit, [double]$st.CurrentBalance) 'SETTLE'
                    } catch {
                        Write-Log "Settle failed for $($b.Symbol): $_" 'ERROR'
                    }
                }
            }
        }
    }

    # 2) Generate a prediction per symbol
    foreach ($sym in $Config.symbols) {
        try {
            $pred = Invoke-Prediction -Symbol $sym -MinConfidence $Config.min_confidence
            Save-Prediction -DataDir $dataDir -P $pred

            $lines = Format-Prediction -P $pred
            foreach ($l in $lines) { Write-Log $l 'SIGNAL' }

            if ($pred.Direction -ne 'NO_TRADE') {
                Write-Log ("Top reasons (4H): " + ($pred.Reasons4H -join ' | ')) 'INFO'
            }

            # 3) Auto-open paper bet if enabled and threshold met
            if ($AutoBet -and $pred.Direction -ne 'NO_TRADE') {
                $state = Get-TrackerState -DataDir $dataDir
                $bal = [double]$state.CurrentBalance
                if ($bal -lt $Config.min_stake_usd) {
                    Write-Log "Balance ${bal:N4} below min stake. Skipping bet." 'WARN'
                    continue
                }
                $stake = [Math]::Round($bal * [double]$pred.KellyFraction, 2)
                $stake = [Math]::Max($stake, $Config.min_stake_usd)
                $stake = [Math]::Min($stake, [Math]::Min($Config.max_stake_usd, $bal))

                # Avoid duplicate open bets per symbol
                $ledger = Join-Path $dataDir 'bets.csv'
                $hasOpen = $false
                if (Test-Path $ledger) {
                    $rows = Import-Csv $ledger
                    $hasOpen = ($rows | Where-Object { $_.Symbol -eq $sym -and $_.Result -eq 'OPEN' }).Count -gt 0
                }
                if ($hasOpen) {
                    Write-Log "Already an OPEN bet for $sym. Skipping new entry." 'WARN'
                    continue
                }

                Add-PendingBet -DataDir $dataDir -Symbol $sym -Direction $pred.Direction `
                    -Stake $stake -EntryPrice $pred.Price -Confidence $pred.Confidence `
                    -Notes ("composite={0};kelly={1}" -f $pred.Composite, $pred.KellyFraction)
                Write-Log ('Opened paper bet: {0} {1} stake ${2:N2} @ ${3:N2}' -f `
                    $sym, $pred.Direction, $stake, [double]$pred.Price) 'BET'
            }
        } catch {
            Write-Log "Prediction failed for ${sym}: $_" 'ERROR'
        }
    }

    # 4) Show projection
    $proj = Get-Projection -DataDir $dataDir -BetsPerDay (24 / 4 * $Config.symbols.Count) `
                -PayoutMultiplier $Config.polymarket_payout_multiplier
    Write-Host ''
    Write-Log ('Projection -> Balance: ${0}  WinRate: {1:P1}  EV/bet: {2}  BetsToGoal: {3}  DaysEst: {4}' -f `
        $proj.CurrentBalance, [double]$proj.WinRate, $proj.EVPerBet,
        $(if ($proj.BetsNeededToGoal) { $proj.BetsNeededToGoal } else { 'inf' }),
        $(if ($proj.DaysToGoalEstimate) { $proj.DaysToGoalEstimate } else { 'n/a' })) 'INFO'
    if ($proj.Note) { Write-Log $proj.Note 'INFO' }
}

# ---- Main ----
if (-not (Test-Path $ConfigPath)) {
    throw "Config not found: $ConfigPath"
}
$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$dataDir = Join-Path $PSScriptRoot $config.data_dir
$logDir  = Join-Path $PSScriptRoot $config.log_dir
foreach ($d in @($dataDir, $logDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
}
$script:LogFile = Join-Path $logDir ("bot-{0:yyyyMMdd}.log" -f (Get-Date))

Initialize-Tracker -DataDir $dataDir `
    -StartingBalance $config.starting_balance_usd `
    -GoalBalance $config.goal_balance_usd

$state = Get-TrackerState -DataDir $dataDir
Show-Banner -Config $config -State $state

if ($Once) {
    Invoke-OneCycle -Config $config -AutoBet:$AutoBet
    return
}

while ($true) {
    try {
        Invoke-OneCycle -Config $config -AutoBet:$AutoBet
    } catch {
        Write-Log "Cycle error: $_" 'ERROR'
    }
    $sleepSec = [int]$config.scan_interval_minutes * 60
    Write-Log ("Sleeping {0} minutes until next scan..." -f $config.scan_interval_minutes) 'INFO'
    Start-Sleep -Seconds $sleepSec
}
