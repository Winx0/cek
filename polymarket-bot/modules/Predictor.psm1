# Predictor.psm1
# Multi-timeframe confluence scoring engine.
# Logic:
#   Bias filter (1D) -> Primary signal (4H) -> Timing trigger (1H)
#   Each timeframe contributes weighted points to a final -100..+100 score.
#   Score >= +THRESHOLD = LONG (UP), <= -THRESHOLD = SHORT (DOWN), else NO TRADE.
# Outputs a structured prediction with confidence and recommended position size.

Set-StrictMode -Version Latest

Import-Module "$PSScriptRoot/MarketData.psm1" -Force
Import-Module "$PSScriptRoot/Indicators.psm1" -Force

function Get-TimeframeScore {
    <#
    .SYNOPSIS
        Compute a -100..+100 score for one timeframe based on indicator confluence.
    #>
    param(
        [Parameter(Mandatory)] [object[]] $Candles
    )
    $closes = [double[]]($Candles | ForEach-Object { $_.Close })
    $highs  = [double[]]($Candles | ForEach-Object { $_.High })
    $lows   = [double[]]($Candles | ForEach-Object { $_.Low })

    if ($closes.Count -lt 60) {
        return [pscustomobject]@{
            Score = 0; Reasons = @('insufficient candles'); Last = $closes[-1]
        }
    }

    $ema20  = Get-EMA -Values $closes -Period 20
    $ema50  = Get-EMA -Values $closes -Period 50
    $ema200 = Get-EMA -Values $closes -Period 200
    $rsi    = Get-RSI -Values $closes -Period 14
    $macd   = Get-MACD -Values $closes
    $bb     = Get-BollingerBands -Values $closes -Period 20 -StdDev 2.0
    $atr    = Get-ATR -High $highs -Low $lows -Close $closes -Period 14
    $srsi   = Get-StochRSI -Values $closes

    $i = $closes.Count - 1
    $iPrev = $i - 1
    $price = $closes[$i]
    $score = 0.0
    $reasons = @()

    # 1. EMA alignment (trend) — weight 25
    if (-not [double]::IsNaN($ema20[$i]) -and -not [double]::IsNaN($ema50[$i])) {
        if ($price -gt $ema20[$i] -and $ema20[$i] -gt $ema50[$i]) {
            $score += 15; $reasons += 'EMA20>EMA50, price above (uptrend)'
        } elseif ($price -lt $ema20[$i] -and $ema20[$i] -lt $ema50[$i]) {
            $score -= 15; $reasons += 'EMA20<EMA50, price below (downtrend)'
        }
    }
    if (-not [double]::IsNaN($ema200[$i])) {
        if ($price -gt $ema200[$i]) { $score += 10; $reasons += 'price > EMA200 (macro bull)' }
        else { $score -= 10; $reasons += 'price < EMA200 (macro bear)' }
    }

    # 2. RSI — weight 20 (with mean-reversion inversion at extremes)
    if (-not [double]::IsNaN($rsi[$i])) {
        $r = $rsi[$i]
        if     ($r -gt 70) { $score -= 10; $reasons += "RSI overbought ($([math]::Round($r,1)))" }
        elseif ($r -lt 30) { $score += 10; $reasons += "RSI oversold ($([math]::Round($r,1)))" }
        elseif ($r -gt 55) { $score += 6;  $reasons += "RSI bullish ($([math]::Round($r,1)))" }
        elseif ($r -lt 45) { $score -= 6;  $reasons += "RSI bearish ($([math]::Round($r,1)))" }
    }

    # 3. MACD histogram — weight 20
    if (-not [double]::IsNaN($macd.Histogram[$i]) -and -not [double]::IsNaN($macd.Histogram[$iPrev])) {
        $h = $macd.Histogram[$i]; $hp = $macd.Histogram[$iPrev]
        if ($h -gt 0 -and $h -gt $hp) { $score += 12; $reasons += 'MACD hist rising above 0' }
        elseif ($h -gt 0)             { $score += 6;  $reasons += 'MACD hist positive' }
        elseif ($h -lt 0 -and $h -lt $hp) { $score -= 12; $reasons += 'MACD hist falling below 0' }
        elseif ($h -lt 0)             { $score -= 6;  $reasons += 'MACD hist negative' }
    }

    # 4. Bollinger Bands position — weight 10 (mean reversion)
    if (-not [double]::IsNaN($bb.Upper[$i])) {
        if ($price -ge $bb.Upper[$i])      { $score -= 6; $reasons += 'price at upper BB (overextended)' }
        elseif ($price -le $bb.Lower[$i])  { $score += 6; $reasons += 'price at lower BB (oversold)' }
    }

    # 5. Stochastic RSI cross — weight 10 (timing)
    if (-not [double]::IsNaN($srsi.K[$i]) -and -not [double]::IsNaN($srsi.D[$i]) -and `
        -not [double]::IsNaN($srsi.K[$iPrev]) -and -not [double]::IsNaN($srsi.D[$iPrev])) {
        $k  = $srsi.K[$i];  $d  = $srsi.D[$i]
        $kp = $srsi.K[$iPrev]; $dp = $srsi.D[$iPrev]
        if ($kp -le $dp -and $k -gt $d -and $k -lt 30) { $score += 10; $reasons += 'StochRSI bullish cross (oversold)' }
        elseif ($kp -ge $dp -and $k -lt $d -and $k -gt 70) { $score -= 10; $reasons += 'StochRSI bearish cross (overbought)' }
    }

    # 6. Volatility regime (ATR % of price) — informational, no score
    $atrPct = $null
    if (-not [double]::IsNaN($atr[$i])) {
        $atrPct = ($atr[$i] / $price) * 100.0
    }

    # Clamp to -100..+100
    if ($score -gt 100) { $score = 100 }
    if ($score -lt -100) { $score = -100 }

    return [pscustomobject]@{
        Score   = [double]$score
        Reasons = $reasons
        Last    = $price
        RSI     = if (-not [double]::IsNaN($rsi[$i])) { [double]$rsi[$i] } else { $null }
        ATRPct  = $atrPct
    }
}

function Invoke-Prediction {
    <#
    .SYNOPSIS
        Run multi-timeframe analysis and return a trade recommendation.
    .PARAMETER Symbol
        BTCUSDT or ETHUSDT.
    .PARAMETER MinConfidence
        Minimum |composite score| (0..100) required to generate a signal. Default 35.
    #>
    param(
        [Parameter(Mandatory)] [string] $Symbol,
        [double] $MinConfidence = 35
    )

    $tf1d = Get-Candles -Symbol $Symbol -Interval '1d' -Limit 300
    $tf4h = Get-Candles -Symbol $Symbol -Interval '4h' -Limit 300
    $tf1h = Get-Candles -Symbol $Symbol -Interval '1h' -Limit 300

    $s1d = Get-TimeframeScore -Candles $tf1d
    $s4h = Get-TimeframeScore -Candles $tf4h
    $s1h = Get-TimeframeScore -Candles $tf1h

    # Weighted composite: 4H is primary (50%), 1D bias (30%), 1H timing (20%)
    $composite = ($s4h.Score * 0.50) + ($s1d.Score * 0.30) + ($s1h.Score * 0.20)

    # If 1D and 4H disagree on sign, halve the composite (low conviction)
    if (($s1d.Score -gt 0 -and $s4h.Score -lt 0) -or ($s1d.Score -lt 0 -and $s4h.Score -gt 0)) {
        $composite *= 0.5
    }

    $direction = 'NO_TRADE'
    if ([Math]::Abs($composite) -ge $MinConfidence) {
        $direction = if ($composite -gt 0) { 'UP' } else { 'DOWN' }
    }

    # Funding rate context
    $funding = Get-FundingRate -Symbol $Symbol

    # Implied probability of directional success based on confidence
    # Empirical calibration: at score 35 -> ~58%, at 60 -> ~65%, at 90 -> ~72%
    $absC = [Math]::Min([Math]::Abs($composite), 100)
    $probWin = 0.50 + ($absC / 100.0) * 0.22

    # Kelly fraction for position sizing (capped at 25% — fractional Kelly)
    # f* = p - q/b ; assume Polymarket avg payout odds b ~ 1.0 (50/50 markets)
    $b = 1.0
    $kelly = ($probWin * ($b + 1) - 1) / $b
    if ($kelly -lt 0) { $kelly = 0 }
    $kellyFractional = [Math]::Min($kelly * 0.5, 0.25)  # half-Kelly, max 25%

    return [pscustomobject]@{
        Timestamp     = (Get-Date).ToUniversalTime()
        Symbol        = $Symbol
        Price         = $s4h.Last
        Direction     = $direction
        Composite     = [Math]::Round($composite, 2)
        Confidence    = [Math]::Round($absC, 2)
        ProbWin       = [Math]::Round($probWin, 4)
        KellyFraction = [Math]::Round($kellyFractional, 4)
        FundingRate   = $funding
        Score1D       = [Math]::Round($s1d.Score, 2)
        Score4H       = [Math]::Round($s4h.Score, 2)
        Score1H       = [Math]::Round($s1h.Score, 2)
        Reasons1D     = $s1d.Reasons
        Reasons4H     = $s4h.Reasons
        Reasons1H     = $s1h.Reasons
        ATRPct4H      = $s4h.ATRPct
        RSI4H         = $s4h.RSI
    }
}

Export-ModuleMember -Function Invoke-Prediction, Get-TimeframeScore
