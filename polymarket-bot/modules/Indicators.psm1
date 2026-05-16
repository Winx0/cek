# Indicators.psm1
# Technical indicators implemented from scratch in pure PowerShell.
# All functions accept arrays of [double] (candle close, high, low, volume).
# Designed to match TradingView/standard formulas.

Set-StrictMode -Version Latest

function Get-SMA {
    param(
        [Parameter(Mandatory)] [double[]] $Values,
        [Parameter(Mandatory)] [int]      $Period
    )
    $result = New-Object double[] $Values.Count
    for ($i = 0; $i -lt $Values.Count; $i++) {
        if ($i -lt $Period - 1) { $result[$i] = [double]::NaN; continue }
        $sum = 0.0
        for ($k = $i - $Period + 1; $k -le $i; $k++) { $sum += $Values[$k] }
        $result[$i] = $sum / $Period
    }
    return ,$result
}

function Get-EMA {
    param(
        [Parameter(Mandatory)] [double[]] $Values,
        [Parameter(Mandatory)] [int]      $Period
    )
    $result = New-Object double[] $Values.Count
    if ($Values.Count -lt $Period) {
        for ($i = 0; $i -lt $Values.Count; $i++) { $result[$i] = [double]::NaN }
        return ,$result
    }
    $multiplier = 2.0 / ($Period + 1)
    # Seed with SMA at index Period-1
    $sum = 0.0
    for ($i = 0; $i -lt $Period; $i++) { $sum += $Values[$i]; $result[$i] = [double]::NaN }
    $result[$Period - 1] = $sum / $Period
    for ($i = $Period; $i -lt $Values.Count; $i++) {
        $result[$i] = ($Values[$i] - $result[$i - 1]) * $multiplier + $result[$i - 1]
    }
    return ,$result
}

function Get-RSI {
    param(
        [Parameter(Mandatory)] [double[]] $Values,
        [int] $Period = 14
    )
    $result = New-Object double[] $Values.Count
    if ($Values.Count -le $Period) {
        for ($i = 0; $i -lt $Values.Count; $i++) { $result[$i] = [double]::NaN }
        return ,$result
    }
    $gains = 0.0; $losses = 0.0
    for ($i = 1; $i -le $Period; $i++) {
        $change = $Values[$i] - $Values[$i - 1]
        if ($change -ge 0) { $gains += $change } else { $losses += -$change }
        $result[$i - 1] = [double]::NaN
    }
    $avgGain = $gains / $Period
    $avgLoss = $losses / $Period
    if ($avgLoss -eq 0) { $result[$Period] = 100.0 }
    else { $result[$Period] = 100.0 - (100.0 / (1 + $avgGain / $avgLoss)) }

    for ($i = $Period + 1; $i -lt $Values.Count; $i++) {
        $change = $Values[$i] - $Values[$i - 1]
        $gain = [Math]::Max($change, 0)
        $loss = [Math]::Max(-$change, 0)
        $avgGain = ($avgGain * ($Period - 1) + $gain) / $Period
        $avgLoss = ($avgLoss * ($Period - 1) + $loss) / $Period
        if ($avgLoss -eq 0) { $result[$i] = 100.0 }
        else { $result[$i] = 100.0 - (100.0 / (1 + $avgGain / $avgLoss)) }
    }
    return ,$result
}

function Get-MACD {
    param(
        [Parameter(Mandatory)] [double[]] $Values,
        [int] $FastPeriod   = 12,
        [int] $SlowPeriod   = 26,
        [int] $SignalPeriod = 9
    )
    $emaFast = Get-EMA -Values $Values -Period $FastPeriod
    $emaSlow = Get-EMA -Values $Values -Period $SlowPeriod
    $macd = New-Object double[] $Values.Count
    for ($i = 0; $i -lt $Values.Count; $i++) {
        if ([double]::IsNaN($emaFast[$i]) -or [double]::IsNaN($emaSlow[$i])) {
            $macd[$i] = [double]::NaN
        } else {
            $macd[$i] = $emaFast[$i] - $emaSlow[$i]
        }
    }
    # Signal line = EMA of MACD (skip NaN in seeding)
    $signal = New-Object double[] $Values.Count
    for ($i = 0; $i -lt $Values.Count; $i++) { $signal[$i] = [double]::NaN }
    $startIdx = ($SlowPeriod - 1)
    if ($Values.Count - $startIdx -ge $SignalPeriod) {
        $multiplier = 2.0 / ($SignalPeriod + 1)
        $sum = 0.0
        for ($i = 0; $i -lt $SignalPeriod; $i++) { $sum += $macd[$startIdx + $i] }
        $signal[$startIdx + $SignalPeriod - 1] = $sum / $SignalPeriod
        for ($i = $startIdx + $SignalPeriod; $i -lt $Values.Count; $i++) {
            $signal[$i] = ($macd[$i] - $signal[$i - 1]) * $multiplier + $signal[$i - 1]
        }
    }
    $hist = New-Object double[] $Values.Count
    for ($i = 0; $i -lt $Values.Count; $i++) {
        if ([double]::IsNaN($macd[$i]) -or [double]::IsNaN($signal[$i])) {
            $hist[$i] = [double]::NaN
        } else {
            $hist[$i] = $macd[$i] - $signal[$i]
        }
    }
    return [pscustomobject]@{
        MACD      = $macd
        Signal    = $signal
        Histogram = $hist
    }
}

function Get-ATR {
    param(
        [Parameter(Mandatory)] [double[]] $High,
        [Parameter(Mandatory)] [double[]] $Low,
        [Parameter(Mandatory)] [double[]] $Close,
        [int] $Period = 14
    )
    $n = $Close.Count
    $tr = New-Object double[] $n
    $tr[0] = $High[0] - $Low[0]
    for ($i = 1; $i -lt $n; $i++) {
        $a = $High[$i] - $Low[$i]
        $b = [Math]::Abs($High[$i] - $Close[$i - 1])
        $c = [Math]::Abs($Low[$i]  - $Close[$i - 1])
        $tr[$i] = [Math]::Max($a, [Math]::Max($b, $c))
    }
    $atr = New-Object double[] $n
    for ($i = 0; $i -lt $n; $i++) { $atr[$i] = [double]::NaN }
    if ($n -lt $Period) { return ,$atr }
    $sum = 0.0
    for ($i = 0; $i -lt $Period; $i++) { $sum += $tr[$i] }
    $atr[$Period - 1] = $sum / $Period
    for ($i = $Period; $i -lt $n; $i++) {
        $atr[$i] = ($atr[$i - 1] * ($Period - 1) + $tr[$i]) / $Period
    }
    return ,$atr
}

function Get-BollingerBands {
    param(
        [Parameter(Mandatory)] [double[]] $Values,
        [int]    $Period = 20,
        [double] $StdDev = 2.0
    )
    $n = $Values.Count
    $mid = Get-SMA -Values $Values -Period $Period
    $upper = New-Object double[] $n
    $lower = New-Object double[] $n
    for ($i = 0; $i -lt $n; $i++) {
        if ($i -lt $Period - 1) {
            $upper[$i] = [double]::NaN; $lower[$i] = [double]::NaN; continue
        }
        $sumSq = 0.0
        for ($k = $i - $Period + 1; $k -le $i; $k++) {
            $sumSq += [Math]::Pow($Values[$k] - $mid[$i], 2)
        }
        $sd = [Math]::Sqrt($sumSq / $Period)
        $upper[$i] = $mid[$i] + $StdDev * $sd
        $lower[$i] = $mid[$i] - $StdDev * $sd
    }
    return [pscustomobject]@{
        Upper  = $upper
        Middle = $mid
        Lower  = $lower
    }
}

function Get-StochRSI {
    param(
        [Parameter(Mandatory)] [double[]] $Values,
        [int] $RsiPeriod   = 14,
        [int] $StochPeriod = 14,
        [int] $KSmooth     = 3,
        [int] $DSmooth     = 3
    )
    $rsi = Get-RSI -Values $Values -Period $RsiPeriod
    $n = $Values.Count
    $stoch = New-Object double[] $n
    for ($i = 0; $i -lt $n; $i++) { $stoch[$i] = [double]::NaN }
    for ($i = $RsiPeriod + $StochPeriod - 1; $i -lt $n; $i++) {
        $minR = [double]::MaxValue
        $maxR = [double]::MinValue
        for ($k = $i - $StochPeriod + 1; $k -le $i; $k++) {
            if ([double]::IsNaN($rsi[$k])) { continue }
            if ($rsi[$k] -lt $minR) { $minR = $rsi[$k] }
            if ($rsi[$k] -gt $maxR) { $maxR = $rsi[$k] }
        }
        if ($maxR -eq $minR) { $stoch[$i] = 50.0 }
        else { $stoch[$i] = (($rsi[$i] - $minR) / ($maxR - $minR)) * 100.0 }
    }
    $k = Get-SMA -Values $stoch -Period $KSmooth
    $d = Get-SMA -Values $k -Period $DSmooth
    return [pscustomobject]@{
        K = $k
        D = $d
    }
}

Export-ModuleMember -Function Get-SMA, Get-EMA, Get-RSI, Get-MACD, Get-ATR, Get-BollingerBands, Get-StochRSI
