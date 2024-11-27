// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract CommunicationContract is Ownable {
    /**
     * @title Message that is emmited outside the BC
     * @param data message to be sent
     * @param sender address of the message sender
     * @param sourceBC Id of the source blockchain
     * @param receiver address of the receiver in the destination blockchain
     * @param destinationBC Id of the blockchain to relay the message to
     * @param fee fee to pay gas fees and the incentive for the relayer
     * @param finalityNBlocks Number of blocks for the message to reach finality
     * @param messageNumber Number of message, unique per destintation blockchain
     */
    struct Message {
        bytes data;
        address sender;
        string sourceBC;
        address receiver;
        string destinationBC;
        uint256 fee;
        uint16 finalityNBlocks;
        uint256 messageNumber;
    }

    /**
     * @notice Indicates that a new message is received within the blockchain
     * @dev
     * @param sender address to pay relayer on source blockchain
     * @param messageData message that is received
     */
    event MessageReceived(address sender, bytes messageData);

    /**
     * @notice Indicates that a new message is sent within the blockchain
     * @dev
     * @param receiver address of the message receiver
     * @param messageData message to be sent
     */
    event MessageSent(address indexed receiver, bytes messageData);

    /**
     * @notice Indicates that a new message is received from outside the blockchain
     * @dev
     * @param relayer address to pay relayer on source blockchain
     * @param message message that is received
     */
    event InboundMessage(address relayer, Message message);

    /**
     * @notice Indicates that a new message is sent outside the blockchain
     * @param message message to be sent
     */
    event OutboundMessage(Message message);

    /**
     * @notice Tracks higher processed incoming messages per source blockchain.
     */
    mapping(string sourceBC => uint256) public incommingMessages;

    /**
     * @notice Tracks unprocessed incoming messages per source blockchain.
     */
    mapping(string sourceBC => uint256[]) public unprocessedMessages;

    /**
     * @notice Tracks outgoing message numbers.
     */
    mapping(string destinationBC => uint256) public outgoingMessages;

    /**
     * @notice Tracks outgoing message fees per destintation blockchain.
     */
    mapping(string destinationBC => mapping(uint256 => uint256))
        public outgoingMessageFees;

    /**
     * @notice Communication contract addreses for destination blockchains.
     */
    mapping(string destinationBC => address) public destinationAddreses;

    constructor(uint256 _messageFee) Ownable(msg.sender) {
        // TODO: Define supported destination/source blockchains
    }

    /**
     * @notice Updates the message fee for an already sent message.
     * @dev
     * @param _destinationBC Destintation blockchain for message.
     * @param _messageNumber Number of message to be updated.
     * @param _extraFee Aditional fee to assign to message.
     */
    function updateMessageFee(
        string calldata _destinationBC,
        uint256 _messageNumber,
        uint256 _extraFee
    ) external onlyOwner {
        // TODO: Implement
    }

    /**
     * @notice Receives a message from other contracts within the chain.
     * @dev
     * @param _message The message to process.
     * @param _receiver Address of receiver in destintation BC.
     * @param _destinationBC Destination BC.
     * @param _finalityNBlocks Number of blocks to reach finality.
     */
    function receiveMessage(
        bytes calldata _messageData,
        address _receiver,
        string calldata _destinationBC,
        uint16 _finalityNBlocks
    ) external payable {
        emit MessageReceived(msg.sender, _messageData);
        require(
            destinationAddreses[_destinationBC] == address(0),
            "Destination blockchain not supported"
        );

        outgoingMessages[_destinationBC]++;

        emit OutboundMessage(
            Message(
                _messageData,
                msg.sender,
                "eth",
                _receiver,
                _destinationBC,
                msg.value,
                _finalityNBlocks,
                outgoingMessages[_destinationBC]
            )
        );
    }

    /**
     * @notice Sends a message to another contract on the same chain.
     * @param targetContract The target contract's address.
     * @param message The message to send.
     */
    function sendMessage(
        address targetContract,
        bytes calldata message,
        bytes32[] calldata proof,
        bytes32 root
    ) external {
        require(targetContract != address(0), "Invalid target address");

        // Verify the Merkle proof before forwarding
        require(verifyMessage(message, proof, root), "Invalid Merkle proof");

        // Call the target contract's function to handle the message
        (bool success, ) = targetContract.call(
            abi.encodeWithSignature("handleMessage(bytes)", message)
        );
        require(success, "Message forwarding failed");

        emit OutboundMessage(targetContract, message);
    }

    /**
     * @notice Sends a message outside chain.
     * @param _message The message to send.
     */
    function outboundsMessage(bytes calldata _message) external payable {
        emit MessageSent(msg.sender, _message);
    }

    /**
     * @notice Receive a message from outside chain.
     * @param _message The message to send.
     */
    function inboundsMessage(bytes calldata _message) external payable {
        emit MessageSent(msg.sender, _message);
    }

    /**
     * @notice Verifies a Merkle proof for an incoming message from an external source.
     * @param message The original message.
     * @param proof The Merkle proof.
     * @param root The Merkle root.
     */
    function verifyMessage(
        bytes calldata message,
        bytes32[] calldata proof,
        bytes32 root
    ) public view returns (bool) {
        bytes32 messageHash = keccak256(message);
        return MerkleProof.verify(proof, root, messageHash);
    }

    //TODO pay Relayer function

    // TODO: Function to add new supported BCs
    // TODO: Function to deposit/withdraw funds from contract -> only for owner
    // TODO: Function to change destination blockchain addresses
}
