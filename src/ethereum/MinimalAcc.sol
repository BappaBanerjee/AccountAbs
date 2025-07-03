// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.28;

import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "lib/account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract MinimalAcc is IAccount, Ownable {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/
    error MinimalAcc_NotEntryPoint();
    error MinimalAcc_NotEntryPointOrOwner();
    error MinimalAcc_CallFailed(bytes);

    IEntryPoint private immutable i_entryPoint;

    /*//////////////////////////////////////////////////////////////
                                 Modifiers
    //////////////////////////////////////////////////////////////*/
    modifier requireFromEntryPoint() {
        if (msg.sender != address(i_entryPoint)) {
            revert MinimalAcc_NotEntryPoint();
        }
        _;
    }

    modifier requireFromEntryPointOrOwner() {
        if (msg.sender != address(i_entryPoint) && msg.sender != owner()) {
            revert MinimalAcc_NotEntryPointOrOwner();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                 CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/
    constructor(address entryPoint) Ownable(msg.sender) {
        i_entryPoint = IEntryPoint(entryPoint);
    }

    /*//////////////////////////////////////////////////////////////
                            RECEIVE FUNCTION
    //////////////////////////////////////////////////////////////*/
    receive() external payable {}

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    /**
     * @notice Executes a function call to a specified address with a given value and data.
     * @param dest The address to which the function call is made.
     * @param value The amount of Ether to send with the function call.
     * @param functionData The data to be sent with the function call.
     */
    // This function is called by the EntryPoint contract or the account owner to execute a function
    // call to a specified address with a given value and data.
    // It uses the low-level `call` function to perform the function call.
    // If the call fails, it reverts with a custom error `MinimalAcc_CallFailed`.
    // Note: This function is external and can be called by the EntryPoint contract or the account owner.
    // It is used to execute arbitrary function calls on other contracts or addresses.
    function execute(address dest, uint256 value, bytes calldata functionData) external requireFromEntryPointOrOwner {
        (bool success, bytes memory result) = dest.call{value: value}(functionData);
        if (!success) {
            revert MinimalAcc_CallFailed(result);
        }
    }

    /**
     * @notice Validates the user operation and pays the prefund amount if necessary.
     * @param userOp The PackedUserOperation containing the user operation data.
     * @param userOpHash The hash of the user operation.
     * @param missingAccountFunds The amount of funds that are missing from the account.
     * @return validationData The validation data indicating success or failure.
     */
    // This function is called by the EntryPoint contract to validate the user operation.
    // It checks the signature of the user operation and pays the prefund amount if necessary.
    // If the signature is valid, it returns SIG_VALIDATION_SUCCESS.
    // If the signature is invalid, it returns SIG_VALIDATION_FAILED.
    // The function also pays the prefund amount to the sender (the account owner) if there are missing funds.
    // The gas limit is set to the maximum value to ensure the transfer succeeds.
    // Note: This function is external and can be called by the EntryPoint contract or the account owner.
    // It is used to validate the user operation and ensure that the account has enough funds to cover the prefund amount.
    // If the account does not have enough funds,
    // it sends the missing amount back to the sender (the account owner) to ensure that
    // the account can continue to operate. This is a security measure to prevent the account from
    // being stuck due to insufficient funds.
    // The function returns the validation data, which indicates whether the signature is valid or not.
    // The validation data is packed as follows:
    // - If the signature is valid, it returns SIG_VALIDATION_SUCCESS.
    // - If the signature is invalid, it returns SIG_VALIDATION_FAILED.
    // - The prefund amount is paid to the sender (the account owner) if there are missing funds.
    // - The gas limit is set to the maximum value to ensure the transfer succeeds.
    // - The function can only be called by the EntryPoint contract or the account owner.
    // - The function is used to validate the user operation and ensure that the account has enough 
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        requireFromEntryPoint
        returns (uint256 validationData)
    {
        validationData = _validateSignature(userOp, userOpHash);
        //_validateNonce
        _payPrefund(missingAccountFunds);
    }

    /*//////////////////////////////////////////////////////////////
                                INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    /**
     * @notice Validates the signature of the user operation.
     * @param userOp The PackedUserOperation containing the user operation data.
     * @param userOpHash The hash of the user operation.
     * @return validationData The validation data indicating success or failure.
     */
    // This function checks the signature of the user operation against the owner's address.
    // If the signature is valid, it returns SIG_VALIDATION_SUCCESS.
    // If the signature is invalid, it returns SIG_VALIDATION_FAILED.   
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        returns (uint256 validationData)
    {
        bytes32 ethSignedMsgHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(ethSignedMsgHash, userOp.signature);
        if (signer != owner()) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }
    /**
     * @notice Pays the prefund amount to the EntryPoint contract if there are missing account funds.
     * @param missingAccountFunds The amount of funds that are missing from the account.
     */
    // This function is called by the EntryPoint contract to pay the prefund amount.
    // It sends the missing funds back to the sender (the account owner).
    // If the prefund amount is zero, it does nothing.
    // If the prefund amount is non-zero, it sends the missing funds to the sender.
    // The gas limit is set to the maximum value to ensure the transfer succeeds.
    // Note: This function is internal and can only be called by the contract itself.
    // It is used to ensure that the account has enough funds to cover the prefund amount.
    // If the account does not have enough funds, it sends the missing amount back to the
    // sender (the account owner) to ensure that the account can continue to operate.
    // This is a security measure to prevent the account from being stuck due to insufficient funds.    
    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            (success);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                GETTERS
    //////////////////////////////////////////////////////////////*/
    /**
     * @notice Returns the address of the EntryPoint contract.
     * @return The address of the EntryPoint contract.
     */
    function getEntryPOint() external view returns (address) {
        return address(i_entryPoint);
    }
}
