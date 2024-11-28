import type { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox-viem";

const config: HardhatUserConfig = {
  solidity: "0.8.27",
  networks: {
    localhost: {
        url: 'http://localhost:8545',
        chainId: 31337, // Default Hardhat network chain ID
        //mining: {
        //  auto: false,
        //  interval: 10_000
        //},
    },
    localhost2: {
      url: "http://localhost:8546",
      chainId: 31337, // Default Hardhat network chain ID  (couldn't make it work with different chain id)
      //mining: {
      //  auto: false,
      //  interval: 10_000
      //},
  },
},
};

export default config;
