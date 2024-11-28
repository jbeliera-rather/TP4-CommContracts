// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { parseEther } from "viem";

// 31337 - Localhost 1
// 31337 - Localhost 2 (couldn't make it work with differnt chain id)
// 1  - Ethereum Mainnet logo
// 56 - BNB Smart Chain Mainnet
// 11155111 - Sepolia Testnet
// 421614 - Arbitrum sepolia Testnet
const CHAIN_IDS: bigint[] = [
  31337n,  // Two hardhat BC with the same data
];
const CHAIN_ADDRESSES: string[] = [
  "0x5FbDB2315678afecb367f032d93F642f64180aa3", // Two hardhat BC with the same data
];
const ONE_GWEI: bigint = parseEther("1");

const Communication = buildModule("Communication", (m) => {
  const chainIds = m.getParameter("chainIds", CHAIN_IDS);
  const chainAddresses = m.getParameter("chainAddresses", CHAIN_ADDRESSES);
  const initialAmount = m.getParameter("initialAmount", ONE_GWEI);

  const incomingCommunication = m.contract("IncomingCommunication", 
    [chainIds], 
    { value: initialAmount}
  );

  const outgoingCommunication = m.contract("OutgoingCommunication", 
    [chainIds, chainAddresses], 
    { value: initialAmount }
  );

  return { incomingCommunication, outgoingCommunication };
});

export default Communication;
