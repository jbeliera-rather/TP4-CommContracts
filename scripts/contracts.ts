import hre from "hardhat";
import { ContractTypesMap } from "hardhat/types/artifacts";
import { parseEther, toHex } from "viem";


async function main() {
    const [firstWalletClient, secondWalletClient] = await hre.viem.getWalletClients();
    const contract: ContractTypesMap["IncomingCommunication"] = await hre.viem.getContractAt(
      "IncomingCommunication",
      "0x5fbdb2315678afecb367f032d93f642f64180aa3",
      //{client: firstWalletClient}
    );
    let response = await contract.read.blocknumberPerChainId([31337n]);
    console.log(response)
    response = await contract.read.getBalance();
    console.log(response)
    await contract.write.setLastBlock([31337n, 3n]);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });