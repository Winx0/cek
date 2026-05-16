# Polymarket BTC/ETH Auto-Predictor (PowerShell)

Bot prediksi otomatis untuk pasar Polymarket "Will BTC/ETH go UP or DOWN?" dengan
modal awal $5 dan target hipotetis $1000. **Bot ini hanya men-generate sinyal
paper-trade — tidak menempatkan order real ke Polymarket.** Anda mengeksekusi
manual di [polymarket.com](https://polymarket.com) berdasarkan output bot.

> **DISCLAIMER:** Trading prediction market berisiko. Target $5 -> $1000 dalam
> 30 hari secara matematis butuh +19.4%/hari (≈ mustahil). Realistic horizon
> dengan strategi solid: 60–90 hari. Anda bisa kehilangan seluruh modal.

---

## Apa yang Bot Lakukan

1. **Tarik OHLCV** BTC/ETH dari Binance (fallback Bybit) di 3 timeframe: 1D, 4H, 1H.
2. **Hitung indikator teknikal** (EMA 20/50/200, RSI, MACD, Bollinger, ATR, Stoch RSI).
3. **Skor confluence** per timeframe (-100..+100) lalu komposit berbobot:
   - 4H = 50% (primary signal)
   - 1D = 30% (bias filter — tidak melawan tren besar)
   - 1H = 20% (timing trigger)
4. **Generate sinyal**: `UP` / `DOWN` / `NO_TRADE` jika |composite| < 35.
5. **Sizing pakai half-Kelly** (max 25% balance) berdasarkan probabilitas menang
   yang dikalibrasi dari skor confidence.
6. **Log paper bet** ke `data/bets.csv`, settle otomatis 4 jam kemudian pakai
   harga spot saat itu.
7. **Project ETA ke $1000** berdasarkan win rate aktual dan EV per bet.

---

## Struktur File

```
polymarket-bot/
├── Start-PolymarketBot.ps1     # entry point
├── config.json                 # parameter (modal, threshold, dll)
├── modules/
│   ├── MarketData.psm1         # fetch klines (Binance + Bybit fallback)
│   ├── Indicators.psm1         # EMA, RSI, MACD, ATR, Bollinger, StochRSI
│   ├── Predictor.psm1          # multi-timeframe scoring + Kelly sizing
│   └── BetTracker.psm1         # CSV ledger + state + projection
├── data/                       # bets.csv, predictions.csv, state.json (auto)
└── logs/                       # bot-YYYYMMDD.log (auto)
```

---

## Cara Pakai

### 1. Persyaratan
- **PowerShell 7+** (`pwsh`). Versi lama Windows PowerShell 5.1 juga jalan tapi
  lebih lambat.
- Akses internet ke `api.binance.com` (atau `api.bybit.com`).

### 2. Sekali-jalan (manual / dry-run)
```powershell
pwsh ./Start-PolymarketBot.ps1 -Once
```
Output: sinyal terkini untuk BTC dan ETH ditulis ke layar + `data/predictions.csv`.

### 3. Mode auto-bet (paper trading kontinu)
```powershell
pwsh ./Start-PolymarketBot.ps1 -AutoBet
```
Bot akan loop tiap `scan_interval_minutes` (default 60). Tekan `Ctrl+C` untuk
menghentikan.

### 4. Schedule via Windows Task Scheduler (paling reliable)
Bikin task yang menjalankan setiap 1 jam pada menit ke-1:

```powershell
$action  = New-ScheduledTaskAction -Execute 'pwsh.exe' `
    -Argument '-NoProfile -File "C:\path\to\polymarket-bot\Start-PolymarketBot.ps1" -Once -AutoBet'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName 'PolymarketBot' -Action $action -Trigger $trigger
```

---

## Konfigurasi (`config.json`)

| Field | Default | Arti |
|---|---|---|
| `symbols` | `["BTCUSDT","ETHUSDT"]` | Pair yang dipantau |
| `starting_balance_usd` | `5.0` | Modal awal |
| `goal_balance_usd` | `1000.0` | Target |
| `min_stake_usd` | `1.0` | Stake minimum per bet |
| `max_stake_usd` | `5.0` | Stake maksimum per bet |
| `min_confidence` | `35` | Threshold composite score untuk trigger sinyal |
| `high_confidence` | `60` | Threshold "high conviction" (untuk dashboard) |
| `scan_interval_minutes` | `60` | Frekuensi loop |
| `polymarket_payout_multiplier` | `1.0` | Asumsi payout odds 1:1 (atur sesuai market) |
| `auto_settle` | `true` | Auto-settle bet 4 jam setelah entry |

---

## Cara Membaca Output

```
[2026-05-16 09:15:00] [SIGNAL] BTCUSDT   | Price: $97,420.00 | Signal: UP   /\ | Score:  48.5  Conf: 48.5%  pWin: 60.7%
[2026-05-16 09:15:00] [SIGNAL]           | 1D:  35.0   4H:  60.0   1H:  35.0   ATR4H: 1.42%   Funding: 0.012%
[2026-05-16 09:15:00] [BET]    Opened paper bet: BTCUSDT UP stake $0.61 @ $97,420.00
```

- **Score**: -100..+100 (negative = bearish, positive = bullish)
- **Conf**: |Score|, semakin tinggi semakin kuat keyakinan
- **pWin**: estimated probability menang (kalibrasi dari skor)
- **Stake**: half-Kelly × balance, dibatasi `max_stake_usd`

---

## Strategi Realistic ke $1000

Dari modul `BetTracker.Get-Projection`:

| Win Rate | EV/bet (b=1) | Bets ke $1k (modal $5, risk 10%) | Hari (4 bets/hari) |
|---|---|---|---|
| 55% | +0.10 | ~558 bets | ~140 hari |
| 60% | +0.20 | ~291 bets | ~73 hari |
| 65% | +0.30 | ~199 bets | ~50 hari |
| 70% | +0.40 | ~152 bets | ~38 hari |

Angka ini compounding ideal — di praktik, drawdown dan fees Polymarket akan
menambah waktu 30-50%. **Realistic plan: 60-90 hari dengan win rate ≥60%.**

---

## Rekomendasi Kerja Sama (Anda + Bot)

1. **Minggu 1-2: paper trading saja** (`-AutoBet` mode). Validasi win rate.
   Kalau di bawah 55%, jangan deploy modal real — kita kalibrasi parameter dulu.
2. **Minggu 3+**: bila win rate ≥60% di paper, mulai eksekusi manual di
   Polymarket sesuai sinyal. Mulai dari $1 per bet.
3. **Review harian**: cek `data/bets.csv` & `data/predictions.csv`. Laporkan
   anomali ke saya untuk tuning bobot indikator.

---

## Limitasi yang Harus Anda Tahu

- **Tidak ada eksekusi real**: Polymarket pakai USDC di Polygon — integrasi
  on-chain lebih kompleks dan butuh approval dari Anda. Bisa ditambahkan nanti.
- **Bias historis**: skor dikalibrasi pakai heuristik standar, bukan backtest
  pada data Polymarket actual. Validasi dengan paper trading dulu.
- **Funding rate sentiment** ditarik tapi belum dipakai untuk scoring (TODO).
- **News/macro events** tidak diawasi (mis. Fed FOMC, CPI release). Hindari
  trading 30 menit sebelum/sesudah event berdampak.

---

## Roadmap (kalau Anda mau lanjut)

- [ ] Backtest 1-2 tahun OHLCV BTC/ETH untuk kalibrasi bobot indikator
- [ ] Integrasi Polymarket CLOB API untuk auto-place order (perlu wallet)
- [ ] Funding rate sebagai sentiment input
- [ ] Economic calendar filter (skip kalau ada event red-folder)
- [ ] Telegram/Discord notification pada sinyal high-confidence
- [ ] Walk-forward validation harian
