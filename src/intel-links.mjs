// Blockchain explorer links for wallet findings (no request is made). Shared by the local and browser editions.
/** Explorer links for a wallet (no request is made) */
export function explorerLinks(type, address) {
    const a = encodeURIComponent(address);
    if (/^Bitcoin testnet/.test(type)) return [`https://blockstream.info/testnet/address/${a}`];
    if (/^Bitcoin \(/.test(type)) return [`https://blockstream.info/address/${a}`, `https://mempool.space/address/${a}`];
    if (/^Litecoin/.test(type)) return [`https://blockchair.com/litecoin/address/${a}`];
    if (/^Dogecoin/.test(type)) return [`https://blockchair.com/dogecoin/address/${a}`];
    if (/^Dash/.test(type)) return [`https://blockchair.com/dash/address/${a}`];
    if (/^Bitcoin Cash/.test(type)) return [`https://blockchair.com/bitcoin-cash/address/${a}`];
    if (/^Zcash/.test(type)) return [`https://blockchair.com/zcash/address/${a}`];
    if (/^Ethereum/.test(type)) return [`https://etherscan.io/address/${a}`, `https://bscscan.com/address/${a}`, `https://polygonscan.com/address/${a}`];
    if (/^TRON/.test(type)) return [`https://tronscan.org/#/address/${a}`];
    if (/^XRP/.test(type)) return [`https://xrpscan.com/account/${a}`];
    if (/^Stellar/.test(type)) return [`https://stellar.expert/explorer/public/account/${a}`];
    if (/^Monero/.test(type)) return []; // Monero addresses are not visible on-chain
    if (/^Solana/.test(type)) return [`https://solscan.io/account/${a}`];
    if (/^TON/.test(type)) return [`https://tonviewer.com/${a}`];
    if (/^Tezos/.test(type)) return [`https://tzkt.io/${a}`];
    if (/^Cardano/.test(type)) return [`https://cardanoscan.io/address/${a}`];
    if (/^Cosmos/.test(type)) return [`https://www.mintscan.io/cosmos/address/${a}`];
    return [];
}

