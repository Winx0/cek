import os
import asyncio
import time
import logging
from web3 import Web3
from aiogram import Bot, Dispatcher, types
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, ReplyKeyboardRemove
from aiogram.dispatcher import FSMContext
from aiogram.dispatcher.filters.state import State, StatesGroup
from aiogram.contrib.fsm_storage.memory import MemoryStorage
from dotenv import load_dotenv

from utils import validate_address, check_token_balance
from trading import execute_buy, execute_sell

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

# Initialize Web3 with correct RPC URL
RPC_URL = os.getenv("RPC_URL", "https://rpc.monad.xyz/")
web3 = Web3(Web3.HTTPProvider(RPC_URL))

# Initialize Bot
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
if not TELEGRAM_BOT_TOKEN:
    logger.error("TELEGRAM_BOT_TOKEN not found in .env")
    exit(1)

# Updated contract addresses from official docs
ROUTER_ADDRESS = os.getenv("ROUTER_ADDRESS", "0xeA8D67e77B029AE77746F00a2Bc3e14faa297A52")
WMOD_ADDRESS = os.getenv("WMOD_ADDRESS", "0x761Ac2b31593A10F7Be71dC61C76463486F31969")

# Initialize bot and dispatcher
bot = Bot(token=TELEGRAM_BOT_TOKEN)
storage = MemoryStorage()
dp = Dispatcher(bot, storage=storage)

# User data storage
user_data = {}

# State Machine
class TradeStates(StatesGroup):
    WAITING_CA = State()
    WAITING_AMOUNT = State()
    CONFIRM_BUY = State()
    CONFIRM_SELL = State()

# Keyboards
def welcome_keyboard():
    return InlineKeyboardMarkup().add(
        InlineKeyboardButton("🚀 Generate Wallet", callback_data="generate_wallet")
    )

def main_menu():
    return InlineKeyboardMarkup(row_width=2).add(
        InlineKeyboardButton("💰 Buy", callback_data="menu_buy"),
        InlineKeyboardButton("📤 Sell", callback_data="menu_sell"),
        InlineKeyboardButton("🏧 Withdraw", callback_data="menu_withdraw"),
        InlineKeyboardButton("📊 Position", callback_data="menu_position"),
        InlineKeyboardButton("🔑 Export Key", callback_data="menu_export")
    )

def confirm_buy_keyboard():
    return InlineKeyboardMarkup().row(
        InlineKeyboardButton("✅ Confirm Buy", callback_data="confirm_buy"),
        InlineKeyboardButton("❌ Cancel", callback_data="cancel_buy")
    )

def sell_percent_keyboard():
    return InlineKeyboardMarkup(row_width=2).add(
        InlineKeyboardButton("25%", callback_data="sell_25"),
        InlineKeyboardButton("50%", callback_data="sell_50"),
        InlineKeyboardButton("75%", callback_data="sell_75"),
        InlineKeyboardButton("100%", callback_data="sell_100")
    )

@dp.message_handler(commands=['start'])
async def start_command(message: types.Message):
    try:
        photo_url = "https://pbs.twimg.com/profile_images/1892295218910941185/pkZ39Bsy_400x400.jpg"
        await bot.send_photo(
            chat_id=message.chat.id,
            photo=photo_url,
            caption="=== MONAD COMMUNITY TEST BOT ===\nUSE WISELY\nLET'S DEGEN PLAY ===",
            parse_mode="Markdown",
            reply_markup=welcome_keyboard()
        )
    except Exception as e:
        logger.error(f"Error in start_command: {e}")
        await message.answer("❌ Error starting bot")

@dp.callback_query_handler(lambda c: c.data == 'generate_wallet')
async def generate_wallet(callback: types.CallbackQuery):
    try:
        account = web3.eth.account.create()
        user_data[callback.from_user.id] = {
            "wallet": {
                "address": account.address,
                "private_key": account.key.hex()
            },
            "balance": 0,
            "token": None
        }

        await callback.message.edit_caption(
            caption=f"🆕 Wallet Created!\n\n📝 Address: `{account.address}`\n\n⚠️ Save your private key securely!",
            parse_mode="Markdown",
            reply_markup=main_menu()
        )
    except Exception as e:
        logger.error(f"Error generating wallet: {e}")
        await callback.message.answer("❌ Failed to create wallet")

@dp.callback_query_handler(lambda c: c.data == 'menu_buy')
async def process_buy(callback: types.CallbackQuery):
    await TradeStates.WAITING_CA.set()
    await callback.message.answer("📥 Enter token Contract Address:", reply_markup=ReplyKeyboardRemove())

@dp.message_handler(state=TradeStates.WAITING_CA)
async def process_ca(message: types.Message, state: FSMContext):
    try:
        raw_input = message.text.strip()
        ca = raw_input.split("/token/")[-1].split("/")[0] if "monadexplorer.com" in raw_input else raw_input
        ca = validate_address(ca)

        if not ca:
            return await message.reply("❌ Contract address tidak valid! Pastikan format address benar.")

        if web3.eth.get_code(ca) == b'\x00':
            return await message.reply("❌ Contract tidak ditemukan! Pastikan token sudah di-deploy.")

        # Get token info with extended ABI
        contract = web3.eth.contract(address=ca, abi=[
            {"inputs": [], "name": "symbol", "outputs": [{"type": "string"}], "type": "function"},
            {"inputs": [], "name": "decimals", "outputs": [{"type": "uint8"}], "type": "function"},
            {"inputs": [], "name": "totalSupply", "outputs": [{"type": "uint256"}], "type": "function"},
            {"inputs": [], "name": "name", "outputs": [{"type": "string"}], "type": "function"}
        ])

        try:
            symbol = contract.functions.symbol().call()
            decimals = contract.functions.decimals().call()
            name = contract.functions.name().call()
            total_supply = contract.functions.totalSupply().call()

            # Format total supply with proper decimals
            total_supply_formatted = total_supply / (10 ** decimals)

            await state.update_data(token={
                'address': ca,
                'symbol': symbol,
                'decimals': decimals,
                'name': name,
                'total_supply': total_supply
            })

            user_data[message.from_user.id]["token"] = {
                'address': ca,
                'symbol': symbol,
                'decimals': decimals,
                'name': name,
                'total_supply': total_supply
            }

            await TradeStates.WAITING_AMOUNT.set()
            await message.answer(
                f"✅ Token Terdeteksi!\n\n"
                f"📜 Nama: {name}\n"
                f"🔤 Symbol: {symbol}\n"
                f"🔢 Decimals: {decimals}\n"
                f"📊 Total Supply: {total_supply_formatted:,.2f} {symbol}\n\n"
                f"💰 Masukkan jumlah MOD yang ingin digunakan:",
                reply_markup=ReplyKeyboardRemove()
            )
        except Exception as e:
            logger.error(f"Error getting token info: {e}")
            await message.reply("❌ Token tidak valid! Pastikan ini adalah token ERC20 yang benar.")

    except Exception as e:
        logger.error(f"Error processing contract: {e}")
        await message.reply("❌ Gagal memproses contract! Silakan coba lagi.")

@dp.message_handler(state=TradeStates.WAITING_AMOUNT)
async def process_amount(message: types.Message, state: FSMContext):
    try:
        amount = float(message.text)
        if amount <= 0:
            return await message.reply("❌ Amount must be greater than 0!")

        user_id = message.from_user.id
        if user_id not in user_data or 'wallet' not in user_data[user_id]:
            return await message.reply("❌ No wallet found! Generate one first.")

        wallet = user_data[user_id]["wallet"]
        mod_balance = web3.eth.get_balance(wallet["address"])

        if mod_balance < web3.to_wei(amount, 'ether'):
            return await message.reply("❌ Insufficient MOD balance!")

        data = await state.get_data()
        token = data['token']

        await state.update_data(amount=amount)
        await TradeStates.CONFIRM_BUY.set()

        await message.answer(
            f"🛒 Buy Order:\n• Token: {token['symbol']}\n• MOD Amount: {amount}\n\nConfirm purchase:",
            reply_markup=confirm_buy_keyboard()
        )
    except ValueError:
        await message.reply("❌ Please enter a valid number!")
    except Exception as e:
        logger.error(f"Error processing amount: {e}")
        await message.reply("❌ Error processing amount!")

@dp.callback_query_handler(lambda c: c.data == 'confirm_buy', state=TradeStates.CONFIRM_BUY)
async def confirm_buy(callback: types.CallbackQuery, state: FSMContext):
    try:
        data = await state.get_data()
        user_id = callback.from_user.id

        if user_id not in user_data or 'wallet' not in user_data[user_id]:
            await callback.message.edit_text("❌ No wallet found!")
            return

        wallet = user_data[user_id]["wallet"]
        token = data['token']
        amount = data['amount']

        # Execute buy transaction
        success, tx_hash, message = await execute_buy(
            web3=web3,
            wallet=wallet,
            token_address=token['address'],
            amount_mod=amount,
            router_address=ROUTER_ADDRESS,
            wmod_address=WMOD_ADDRESS
        )

        if success:
            await callback.message.edit_text(
                f"✅ Buy Successful!\n• Token: {token['symbol']}\n• Amount: {amount} MOD\n• Tx: `{tx_hash}`",
                parse_mode="Markdown"
            )
        else:
            await callback.message.edit_text(f"❌ Buy Failed: {message}")

    except Exception as e:
        logger.error(f"Error in buy confirmation: {e}")
        await callback.message.edit_text("❌ Transaction failed!")
    finally:
        await state.finish()

@dp.callback_query_handler(lambda c: c.data.startswith("sell_"))
async def handle_sell(callback: types.CallbackQuery):
    try:
        user_id = callback.from_user.id
        if user_id not in user_data or 'wallet' not in user_data[user_id]:
            await callback.message.edit_text("❌ No wallet found!")
            return

        percentage = int(callback.data.split("_")[1])
        wallet = user_data[user_id]["wallet"]
        token = user_data[user_id]["token"]

        if not token:
            await callback.message.edit_text("❌ No token selected!")
            return

        success, tx_hash, message = await execute_sell(
            web3=web3,
            wallet=wallet,
            token_address=token['address'],
            sell_percentage=percentage,
            router_address=ROUTER_ADDRESS,
            wmod_address=WMOD_ADDRESS
        )

        if success:
            await callback.message.edit_text(
                f"✅ Sell Successful!\n• Token: {token['symbol']}\n• Amount: {percentage}%\n• Tx: `{tx_hash}`",
                parse_mode="Markdown"
            )
        else:
            await callback.message.edit_text(f"❌ Sell Failed: {message}")

    except Exception as e:
        logger.error(f"Error in sell execution: {e}")
        await callback.message.edit_text("❌ Sell transaction failed!")

async def main():
    try:
        await dp.start_polling()
    except Exception as e:
        logger.error(f"Error in main: {e}")

if __name__ == "__main__":
    print("🔥 Monad DEX Bot is active!")
    asyncio.run(main())