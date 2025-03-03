import logging
from web3 import Web3
from typing import Dict, Any, Optional, Union
from decimal import Decimal

logger = logging.getLogger(__name__)

def validate_address(address: str) -> Optional[str]:
    """Validate and return checksum address"""
    try:
        if not address or not isinstance(address, str):
            return None
        return Web3.to_checksum_address(address)
    except Exception as e:
        logger.error(f"Invalid address format: {e}")
        return None

def check_token_balance(web3: Web3, token_contract: Any, wallet_address: str) -> float:
    """Check token balance for a given wallet"""
    try:
        balance = token_contract.functions.balanceOf(wallet_address).call()
        decimals = token_contract.functions.decimals().call()
        return float(Decimal(balance) / Decimal(10 ** decimals))
    except Exception as e:
        logger.error(f"Error checking token balance: {e}")
        return 0.0

def check_token_approval(web3: Web3, token_contract: Any, owner: str, spender: str) -> bool:
    """Check if token is approved for trading"""
    try:
        allowance = token_contract.functions.allowance(owner, spender).call()
        return allowance > Web3.to_wei(1000000, 'ether')  # Consider approved if allowance is high
    except Exception as e:
        logger.error(f"Error checking token approval: {e}")
        return False

def estimate_gas_with_buffer(web3: Web3, tx: Dict[str, Any], buffer_percent: int = 20) -> int:
    """Estimate gas with safety buffer"""
    try:
        # Add from address if not present (required for estimate_gas)
        if 'from' not in tx and 'value' in tx:
            tx['from'] = tx['from'] if 'from' in tx else web3.eth.accounts[0]

        estimated_gas = web3.eth.estimate_gas(tx)
        buffered_gas = int(estimated_gas * (1 + buffer_percent/100))

        # Cap at block gas limit
        block_gas_limit = web3.eth.get_block('latest')['gasLimit']
        return min(buffered_gas, block_gas_limit - 100000)  # Leave some room below block gas limit

    except Exception as e:
        logger.error(f"Error estimating gas: {e}")
        return 300000  # Fallback to safe default

def format_amount_with_decimals(amount: Union[int, float], decimals: int) -> str:
    """Format token amount with proper decimal places"""
    try:
        if isinstance(amount, float):
            amount = int(amount * (10 ** decimals))
        decimal_str = str(Decimal(amount) / Decimal(10 ** decimals))
        return decimal_str.rstrip('0').rstrip('.') if '.' in decimal_str else decimal_str
    except Exception as e:
        logger.error(f"Error formatting amount: {e}")
        return str(amount)

def validate_and_normalize_percentage(percentage: Union[int, float]) -> Optional[int]:
    """Validate and normalize sell percentage"""
    try:
        percentage = float(percentage)
        if not 0 < percentage <= 100:
            return None
        return int(percentage)
    except (ValueError, TypeError):
        return None