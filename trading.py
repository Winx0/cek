import time
import logging
from web3 import Web3
from typing import Dict, Any, Tuple
from decimal import Decimal
from utils import check_token_balance, check_token_approval, estimate_gas_with_buffer

logger = logging.getLogger(__name__)

ROUTER_ABI = [
    {
        "name": "swapExactETHForTokens",
        "type": "function",
        "inputs": [
            {"name": "amountOutMin", "type": "uint256"},
            {"name": "path", "type": "address[]"},
            {"name": "to", "type": "address"},
            {"name": "deadline", "type": "uint256"}
        ],
        "outputs": [{"name": "amounts", "type": "uint256[]"}],
        "stateMutability": "payable"
    },
    {
        "name": "swapExactTokensForETH",
        "type": "function",
        "inputs": [
            {"name": "amountIn", "type": "uint256"},
            {"name": "amountOutMin", "type": "uint256"},
            {"name": "path", "type": "address[]"},
            {"name": "to", "type": "address"},
            {"name": "deadline", "type": "uint256"}
        ],
        "outputs": [{"name": "amounts", "type": "uint256[]"}],
        "stateMutability": "nonpayable"
    },
    {
        "name": "getAmountsOut",
        "type": "function",
        "inputs": [
            {"name": "amountIn", "type": "uint256"},
            {"name": "path", "type": "address[]"}
        ],
        "outputs": [{"name": "amounts", "type": "uint256[]"}],
        "stateMutability": "view"
    }
]

ERC20_ABI = [
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [
            {"name": "spender", "type": "address"},
            {"name": "amount", "type": "uint256"}
        ],
        "name": "approve",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    }
]

async def execute_buy(
    web3: Web3,
    wallet: Dict[str, str],
    token_address: str,
    amount_mod: float,
    router_address: str,
    wmod_address: str,
    slippage_percent: float = 3.0
) -> Tuple[bool, str, str]:
    """
    Execute buy transaction with enhanced error handling and slippage protection
    """
    try:
        # Validate addresses
        token_address = Web3.to_checksum_address(token_address)
        router_address = Web3.to_checksum_address(router_address)
        wmod_address = Web3.to_checksum_address(wmod_address)

        # Check MOD balance with detailed error
        mod_balance = web3.eth.get_balance(wallet['address'])
        required_mod = web3.to_wei(amount_mod, 'ether')

        if mod_balance < required_mod:
            available_mod = web3.from_wei(mod_balance, 'ether')
            return False, "", f"❌ Insufficient MOD balance. Available: {available_mod:.4f} MOD"

        router_contract = web3.eth.contract(address=router_address, abi=ROUTER_ABI)

        # Get expected output amount for slippage calculation
        try:
            amounts_out = router_contract.functions.getAmountsOut(
                required_mod,
                [wmod_address, token_address]
            ).call()
            min_amount_out = int(amounts_out[1] * (1 - slippage_percent/100))
        except Exception as e:
            logger.error(f"Error calculating amounts out: {e}")
            min_amount_out = 0  # Fallback to accepting any amount

        # Prepare transaction
        deadline = int(time.time()) + 300
        swap_params = [
            min_amount_out,
            [wmod_address, token_address],
            wallet['address'],
            deadline
        ]

        # Build transaction with proper gas settings
        tx = router_contract.functions.swapExactETHForTokens(
            *swap_params
        ).build_transaction({
            'from': wallet['address'],
            'value': required_mod,
            'nonce': web3.eth.get_transaction_count(wallet['address']),
            'gasPrice': Web3.to_wei(55, 'gwei')  # Fixed 55 Gwei
        })

        # Estimate gas with 20% buffer
        tx['gas'] = estimate_gas_with_buffer(web3, tx)

        # Execute transaction
        signed_tx = web3.eth.account.sign_transaction(tx, wallet['private_key'])
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)

        # Wait for transaction receipt with timeout
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)

        if receipt['status'] == 1:
            return True, web3.to_hex(tx_hash), "✅ Buy transaction successful"
        else:
            return False, web3.to_hex(tx_hash), "❌ Transaction reverted"

    except Exception as e:
        error_msg = str(e).lower()
        if "insufficient funds" in error_msg:
            return False, "", "❌ Insufficient MOD for gas fees"
        elif "execution reverted" in error_msg:
            return False, "", "❌ Transaction reverted - possible high slippage or liquidity issues"

        logger.error(f"Buy execution error: {e}")
        return False, "", f"❌ Error: {str(e)[:100]}"

async def execute_sell(
    web3: Web3,
    wallet: Dict[str, str],
    token_address: str,
    sell_percentage: int,
    router_address: str,
    wmod_address: str,
    slippage_percent: float = 3.0
) -> Tuple[bool, str, str]:
    """
    Execute sell transaction with percentage amount and slippage protection
    """
    try:
        # Validate addresses
        token_address = Web3.to_checksum_address(token_address)
        router_address = Web3.to_checksum_address(router_address)
        wmod_address = Web3.to_checksum_address(wmod_address)

        token_contract = web3.eth.contract(address=token_address, abi=ERC20_ABI)
        router_contract = web3.eth.contract(address=router_address, abi=ROUTER_ABI)

        # Check token balance
        token_balance = token_contract.functions.balanceOf(wallet['address']).call()
        if token_balance == 0:
            return False, "", "❌ No tokens to sell"

        # Calculate sell amount
        sell_amount = (token_balance * sell_percentage) // 100

        # Check and set approval if needed
        if not check_token_approval(web3, token_contract, wallet['address'], router_address):
            try:
                approve_tx = token_contract.functions.approve(
                    router_address,
                    2**256 - 1  # Max approval
                ).build_transaction({
                    'from': wallet['address'],
                    'nonce': web3.eth.get_transaction_count(wallet['address']),
                    'gasPrice': Web3.to_wei(55, 'gwei')
                })

                approve_tx['gas'] = estimate_gas_with_buffer(web3, approve_tx)
                signed_approve = web3.eth.account.sign_transaction(approve_tx, wallet['private_key'])
                approve_tx_hash = web3.eth.send_raw_transaction(signed_approve.raw_transaction)
                receipt = web3.eth.wait_for_transaction_receipt(approve_tx_hash, timeout=300)

                if receipt['status'] != 1:
                    return False, "", "❌ Token approval failed"

            except Exception as e:
                logger.error(f"Approval error: {e}")
                return False, "", "❌ Failed to approve token"

        # Get expected output amount for slippage calculation
        try:
            amounts_out = router_contract.functions.getAmountsOut(
                sell_amount,
                [token_address, wmod_address]
            ).call()
            min_amount_out = int(amounts_out[1] * (1 - slippage_percent/100))
        except Exception as e:
            logger.error(f"Error calculating amounts out: {e}")
            min_amount_out = 0  # Fallback to accepting any amount

        # Prepare sell transaction
        deadline = int(time.time()) + 300
        tx = router_contract.functions.swapExactTokensForETH(
            sell_amount,
            min_amount_out,
            [token_address, wmod_address],
            wallet['address'],
            deadline
        ).build_transaction({
            'from': wallet['address'],
            'nonce': web3.eth.get_transaction_count(wallet['address']),
            'gasPrice': Web3.to_wei(55, 'gwei')
        })

        tx['gas'] = estimate_gas_with_buffer(web3, tx)

        # Execute transaction
        signed_tx = web3.eth.account.sign_transaction(tx, wallet['private_key'])
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)

        receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)

        if receipt['status'] == 1:
            return True, web3.to_hex(tx_hash), "✅ Sell transaction successful"
        else:
            return False, web3.to_hex(tx_hash), "❌ Transaction reverted"

    except Exception as e:
        error_msg = str(e).lower()
        if "insufficient funds" in error_msg:
            return False, "", "❌ Insufficient MOD for gas fees"
        elif "execution reverted" in error_msg:
            return False, "", "❌ Transaction reverted - possible high slippage or liquidity issues"

        logger.error(f"Sell execution error: {e}")
        return False, "", f"❌ Error: {str(e)[:100]}"