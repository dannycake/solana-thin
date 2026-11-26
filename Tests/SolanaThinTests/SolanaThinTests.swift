import XCTest
import SolanaThin

final class SolanaThinTests: XCTestCase {

    /// The fields of the fixture this test reads; other keys in the file are ignored.
    private struct Vector: Decodable {
        let validator_set: String
        let validator_set_hash: String
        let proof_of_first_transaction: String
        let first_signature: String
        let epoch: UInt64
        let slot: UInt64
        let block_id: String
        let shred_version: UInt16
    }

    /// Decode a lowercase hex string to bytes.
    private func unhex(_ text: String) -> Data {
        precondition(text.count % 2 == 0, "odd-length hex")
        var bytes = Data(capacity: text.count / 2)
        var i = text.startIndex
        while i < text.endIndex {
            let j = text.index(i, offsetBy: 2)
            bytes.append(UInt8(text[i..<j], radix: 16)!)
            i = j
        }
        return bytes
    }

    func testMainnetFirstTransaction() throws {
        let url = Bundle.module.url(
            forResource: "mainnet-block-473100911",
            withExtension: "json",
            subdirectory: "vectors"
        )!
        let vector = try JSONDecoder().decode(Vector.self, from: Data(contentsOf: url))

        let validatorSet = unhex(vector.validator_set)
        let validatorSetHash = unhex(vector.validator_set_hash)
        let proof = unhex(vector.proof_of_first_transaction)
        let firstSignature = unhex(vector.first_signature)

        // One verifier for the cluster; it trusts nothing until a set is pinned.
        let verifier = Verifier.mainnet(shredVersion: vector.shred_version)
        try verifier.pinValidatorSet(
            epoch: vector.epoch,
            set: validatorSet,
            pinnedHash: validatorSetHash
        )

        let tx = try verifier.verifyTransaction(proof: proof)

        let txidHex = tx.transactionId.map { String(format: "%02x", $0) }.joined()
        print("VERIFIED slot=\(tx.slot) finality=\(tx.finality) epoch=\(tx.epoch) transactionId=\(txidHex)")

        XCTAssertEqual(tx.slot, 473100911)
        XCTAssertEqual(tx.finality, .fast)
        XCTAssertEqual(tx.epoch, 1095)
        XCTAssertEqual(tx.transactionId, firstSignature)
    }
}
