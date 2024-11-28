// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

// For debugging -- Comment for deployment
import "hardhat/console.sol";

contract OutgoingCommunication is Ownable {
    /**
     * @notice Status for outgoing messaages
     */
    enum OutgoingMsgStatus {
        Undefined,
        Emitted,
        Payed,
        Cancelled
    }

    /**
     * @notice Indicates that a new message is sent outside the blockchain
     * @param data message to be sent
     * @param sender address of the message sender
     * @param receiver address of the receiver in the destination blockchain
     * @param destinationBC Id of the blockchain to relay the message to
     * @param fee fee to pay gas fees and the incentive for the relayer
     * @param finalityNBlocks Number of blocks for the message to reach finality
     * @param messageNumber Number of message, unique per destintation blockchain
     * @param taxi Indicates whether bus or taxi is used for reception confirmation event
     */
    event OutboundMessage(
        bytes data,
        address sender,
        address receiver,
        uint256 destinationBC,
        uint256 fee,
        uint16 finalityNBlocks,
        uint256 messageNumber,
        bool taxi
    );

    /**
     * @notice Indicates that the fees associated to a previously emmited msg are updated
     * @param destinationBC Id of the blockchain to relay the message to
     * @param fee fee to pay gas fees and the incentive for the relayer
     * @param messageNumber Number of message, unique per destination blockchain
     */
    event UpdateMessageFee(
        uint256 destinationBC,
        uint256 fee,
        uint256 messageNumber
    );

    /**
     * @notice Tracks processed outgoing message status per destination blockchain.
     */
    mapping(uint256 => mapping(uint256 => OutgoingMsgStatus))
        public outMsgStatusPerChainIdAndMsgNumber;

    /**
     * @notice Tracks outgoing message numbers.
     */
    mapping(uint256 => uint256) public outgoingMsgNumberPerDestChain;

    /**
     * @notice Tracks message fees per destintation blockchain.
     */
    mapping(uint256 => mapping(uint256 => uint256))
        public msgFeePerDestChainIdAndNumber;

    /**
     * @notice Communication contract addreses per destination blockchain.
     */
    mapping(uint256 => address) public destAddresesPerChainId;

    constructor(
        uint256[] memory _blockChainIds,
        address[] memory _blockChainAddresses
    ) payable Ownable(msg.sender) {
        for (uint i = 0; i < _blockChainIds.length; i++) {
            destAddresesPerChainId[_blockChainIds[i]] = _blockChainAddresses[i];
        }
    }

    /**
     * @notice Updates the message fee for an already emitted message.
     * @dev
     * @param _destinationBC Destintation blockchain for message.
     * @param _messageNumber Number of message to be updated.
     */
    function updateMessageFee(
        uint256 _destinationBC,
        uint256 _messageNumber
    ) external payable {
        if (
            outMsgStatusPerChainIdAndMsgNumber[_destinationBC][
                _messageNumber
            ] == OutgoingMsgStatus.Undefined
        ) {
            revert("Trying to update the fee for an undefined message");
        }
        if (
            outMsgStatusPerChainIdAndMsgNumber[_destinationBC][
                _messageNumber
            ] == OutgoingMsgStatus.Payed
        ) {
            revert(
                "Trying to update the fee for an already delivered and paid message"
            );
        }
        if (
            outMsgStatusPerChainIdAndMsgNumber[_destinationBC][
                _messageNumber
            ] == OutgoingMsgStatus.Cancelled
        ) {
            revert("Trying to update the fee for a cancelled message");
        }
        msgFeePerDestChainIdAndNumber[_destinationBC][_messageNumber] += msg
            .value;
        emit UpdateMessageFee(
            _destinationBC,
            msgFeePerDestChainIdAndNumber[_destinationBC][_messageNumber],
            _messageNumber
        );
    }

    /**
     * @notice send a message from other contracts within the chain and forward it outside the chain.
     * @dev
     * @param _message The message to process.
     * @param _receiver Address of receiver in destintation BC.
     * @param _destinationBC Destination BC.
     * @param _finalityNBlocks Number of blocks to reach finality.
     * @param _taxi Whether delivery event is emmited as soon as possible with the
     * associated extra cost or it waits to pool suficient ammount of msg deliveries.
     */
    function sendMessage(
        bytes calldata _messageData,
        address _receiver,
        uint256 _destinationBC,
        uint16 _finalityNBlocks,
        bool _taxi
    ) external payable {
        console.log(_destinationBC);
        require(
            destAddresesPerChainId[_destinationBC] != address(0),
            "Destination blockchain not supported"
        );

        console.log("sendMessage Function");

        outgoingMsgNumberPerDestChain[_destinationBC]++;

        emit OutboundMessage(
            _messageData,
            msg.sender,
            _receiver,
            _destinationBC,
            msg.value,
            _finalityNBlocks,
            outgoingMsgNumberPerDestChain[_destinationBC],
            _taxi
        );
    }
    // TODO: pay Relayer function (check message delivery)
    // TODO: Function to add new supported BCs (require contract owner)
    // TODO: Function to deposit/withdraw funds from contract (require contract owner)
    // TODO: Function to change destination blockchain addresses (require contract owner)
}
