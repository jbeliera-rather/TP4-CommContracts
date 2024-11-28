import hre from "hardhat";
import { ContractTypesMap } from "hardhat/types/artifacts";
import { parseEther, toHex } from "viem";

async function main() {
    const [firstWalletClient, secondWalletClient] = await hre.viem.getWalletClients();
    const publicClient = await hre.viem.getPublicClient();
    const contract: ContractTypesMap["OutgoingCommunication"] = await hre.viem.getContractAt(
      "OutgoingCommunication",
      "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
    );
    
    let balance = await publicClient.getBalance({ 
      address: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
     });
    console.log("Contract balance:", balance, "wei");

    const transactionHash = await contract.write.sendMessage(
      [toHex("Mensaje de Prueba"),
       firstWalletClient.account.address,
       31338n,
       12,
       true
      ],
      {
        value: parseEther("0.1"),
        account: firstWalletClient.account
      } );
    
    const event = await publicClient.createEventFilter({
        address: '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512',
      })
    console.log("event received:", event);
  
    const receipt = await publicClient.waitForTransactionReceipt({ hash: transactionHash });
    console.log("Transaction mined:", receipt);

    balance = await publicClient.getBalance({ 
      address: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
     });
     
    console.log("Block Number:", await publicClient.getBlockNumber());
    console.log("Contract balance:", balance, "wei");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });