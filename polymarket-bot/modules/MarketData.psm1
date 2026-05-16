# MarketData.psm1
# Fetches OHLCV candle data from Binance public API (no auth required).
# Falls back to Bybit if Binance is geo-blocked.

Set-StrictMode -Version Latest

$script:BinanceBase = 'https://api.binance.com/api/v3/klines'
$script:BybitBase   = 'https://api.bybit.com/v5/market/kline'

function Get-Candles {
    <#
    .SYNOPSIS
        Fetch OHLCV candles for a symbol/interval from Binance with Bybit fallback.
    .PARAMETER Symbol
        Trading pair, e.g. 'BTCUSDT', 'ETHUSDT'.
    .PARAMETER Interval
        Candle interval: 1m, 5m, 15m, 1h, 4h, 1d.
    .PARAMETER Limit
        Number of candles (max 1000).
    #>
    param(
        [Parameter(Mandatory)] [string] $Symbol,
        [Parameter(Mandatory)] [ValidateSet('1m','5m','15m','30m','1h','2h','4h','6h','12h','1d','1w')]
                                [string] $Interval,
        [int] $Limit = 300
    )

    $candles = $null
    try {
        $url = "$script:BinanceBase`?symbol=$Symbol&interval=$Interval&limit=$Limit"
        $raw = Invoke-RestMethod -Uri $url -TimeoutSec 15 -ErrorAction Stop
        $candles = foreach ($k in $raw) {
            [pscustomobject]@{
                OpenTime  = [datetimeoffset]::FromUnixTimeMilliseconds([int64]$k[0]).UtcDateTime
                Open      = [double]$k[1]
                High      = [double]$k[2]
                Low       = [double]$k[3]
                Close     = [double]$k[4]
                Volume    = [double]$k[5]
                CloseTime = [datetimeoffset]::FromUnixTimeMilliseconds([int64]$k[6]).UtcDateTime
            }
        }
    } catch {
        Write-Verbose "Binance fetch failed: $_. Trying Bybit fallback."
        try {
            $bybitInterval = switch ($Interval) {
                '1m' {'1'} '5m' {'5'} '15m' {'15'} '30m' {'30'}
                '1h' {'60'} '2h' {'120'} '4h' {'240'} '6h' {'360'} '12h' {'720'}
                '1d' {'D'} '1w' {'W'}
            }
            $url = "$script:BybitBase`?category=spot&symbol=$Symbol&interval=$bybitInterval&limit=$Limit"
            $resp = Invoke-RestMethod -Uri $url -TimeoutSec 15 -ErrorAction Stop
            if ($resp.retCode -ne 0) { throw "Bybit error: $($resp.retMsg)" }
            # Bybit returns newest first; reverse to oldest first.
            $list = @($resp.result.list) | Sort-Object { [int64]$_[0] }
            $candles = foreach ($k in $list) {
                [pscustomobject]@{
                    OpenTime  = [datetimeoffset]::FromUnixTimeMilliseconds([int64]$k[0]).UtcDateTime
                    Open      = [double]$k[1]
                    High      = [double]$k[2]
                    Low       = [double]$k[3]
                    Close     = [double]$k[4]
                    Volume    = [double]$k[5]
                    CloseTime = [datetimeoffset]::FromUnixTimeMilliseconds([int64]$k[0] + 1).UtcDateTime
                }
            }
        } catch {
            throw "Both Binance and Bybit failed for $Symbol/$Interval`: $_"
        }
    }
    return ,@($candles)
}

function Get-CurrentPrice {
    param(
        [Parameter(Mandatory)] [string] $Symbol
    )
    try {
        $url = "https://api.binance.com/api/v3/ticker/price?symbol=$Symbol"
        $r = Invoke-RestMethod -Uri $url -TimeoutSec 10 -ErrorAction Stop
        return [double]$r.price
    } catch {
        $url = "https://api.bybit.com/v5/market/tickers?category=spot&symbol=$Symbol"
        $r = Invoke-RestMethod -Uri $url -TimeoutSec 10
        return [double]$r.result.list[0].lastPrice
    }
}

function Get-FundingRate {
    <#
    .SYNOPSIS
        Get latest funding rate (perpetual futures) — useful sentiment indicator.
        Positive = longs paying shorts (bullish bias possibly overheated).
        Negative = shorts paying longs (bearish bias possibly oversold).
    #>
    param(
        [Parameter(Mandatory)] [string] $Symbol
    )
    try {
        $url = "https://fapi.binance.com/fapi/v1/premiumIndex?symbol=$Symbol"
        $r = Invoke-RestMethod -Uri $url -TimeoutSec 10
        return [double]$r.lastFundingRate
    } catch {
        return [double]::NaN
    }
}

Export-ModuleMember -Function Get-Candles, Get-CurrentPrice, Get-FundingRate
