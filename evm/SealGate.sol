// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import { IEAS, AttestationRequest, AttestationRequestData, RevocationRequest, RevocationRequestData, Attestation }
    from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";

/// @title SealGate
/// @notice The attester that the Seal Intelligent Contract speaks through on the Ethereum Attestation Service.
///         EAS takes nested structs, and an attestation's UID is only known once it is made, so this gate takes Seal's
///         flat calls, makes the EAS call, and remembers which UID belongs to which of Seal's records. It accepts calls
///         from Seal alone. On EAS, every Seal attestation therefore has this contract as its attester: an app that
///         trusts Seal trusts attester == this address, on Seal's one schema.
contract SealGate {
    IEAS public immutable eas;
    bytes32 public immutable schema;
    address private immutable deployer;
    address public seal;

    mapping(bytes32 => bytes32) public uidOf;

    event Sealed(bytes32 indexed key, bytes32 indexed uid, address indexed recipient);
    event Unsealed(bytes32 indexed key, bytes32 indexed uid);

    error AlreadySet();
    error NotSeal();
    error Exists();
    error Unknown();

    constructor(address eas_, bytes32 schema_) {
        eas = IEAS(eas_);
        schema = schema_;
        deployer = msg.sender;
    }

    /// One time wiring: the gate is deployed before the Intelligent Contract that speaks through it.
    function setSeal(address seal_) external {
        if (msg.sender != deployer || seal != address(0) || seal_ == address(0)) revert AlreadySet();
        seal = seal_;
    }

    function attest(bytes32 key, address recipient, string calldata claim, string calldata source) external {
        if (msg.sender != seal) revert NotSeal();
        if (uidOf[key] != bytes32(0)) revert Exists();
        bytes32 uid = eas.attest(AttestationRequest({
            schema: schema,
            data: AttestationRequestData({
                recipient: recipient,
                expirationTime: 0,
                revocable: true,
                refUID: bytes32(0),
                data: abi.encode(claim, source),
                value: 0
            })
        }));
        uidOf[key] = uid;
        emit Sealed(key, uid, recipient);
    }

    function revoke(bytes32 key) external {
        if (msg.sender != seal) revert NotSeal();
        bytes32 uid = uidOf[key];
        if (uid == bytes32(0)) revert Unknown();
        eas.revoke(RevocationRequest({ schema: schema, data: RevocationRequestData({ uid: uid, value: 0 }) }));
        emit Unsealed(key, uid);
    }

    /// Flat state of one of Seal's records, for readers that decode only static tuples.
    function state(bytes32 key) external view returns (bytes32 uid, bool revoked) {
        uid = uidOf[key];
        if (uid != bytes32(0)) revoked = eas.getAttestation(uid).revocationTime != 0;
    }
}
