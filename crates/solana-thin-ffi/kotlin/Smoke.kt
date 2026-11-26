// Drives the verifier through the generated Kotlin binding on the JVM, with
// a real mainnet block: Smoke <directory written by the smoke_vectors example>.
//
// This file is also the Kotlin side's record of the interface. The `when`
// expressions have no `else`, `Through` overrides every method, and the
// record is built with every field named, so that a case, a method or a
// field added to or taken from the Rust side stops this file compiling.

import java.io.File
import uniffi.solana_thin_ffi.Finality
import uniffi.solana_thin_ffi.VerifiedTransaction
import uniffi.solana_thin_ffi.Verifier
import uniffi.solana_thin_ffi.VerifierInterface
import uniffi.solana_thin_ffi.VerifyException

fun unhex(text: String) = ByteArray(text.length / 2) { text.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

/** The case of an error and the verifier's sentence about it. */
fun describe(error: VerifyException): Pair<String, String> = when (error) {
    is VerifyException.Malformed -> "Malformed" to error.detail
    is VerifyException.Unsupported -> "Unsupported" to error.detail
    is VerifyException.LimitExceeded -> "LimitExceeded" to error.detail
    is VerifyException.InvalidValidatorSet -> "InvalidValidatorSet" to error.detail
    is VerifyException.EpochNotPinned -> "EpochNotPinned" to error.detail
    is VerifyException.CertificateRejected -> "CertificateRejected" to error.detail
    is VerifyException.ProofRejected -> "ProofRejected" to error.detail
    is VerifyException.WrongTransaction -> "WrongTransaction" to error.detail
    is VerifyException.UnprovableBlock -> "UnprovableBlock" to error.detail
    is VerifyException.InvalidParameters -> "InvalidParameters" to error.detail
    is VerifyException.Other -> "Other" to error.detail
}

fun name(finality: Finality): String = when (finality) {
    Finality.FAST -> "fast"
    Finality.SLOW -> "slow"
}

/** Every method of a verifier, overridden by hand. The calls below go through it. */
class Through(private val inner: Verifier) : VerifierInterface {
    override fun forgetEpoch(epoch: ULong): Boolean = inner.forgetEpoch(epoch)

    override fun forgetEpochsBefore(epoch: ULong): ULong = inner.forgetEpochsBefore(epoch)

    override fun pinValidatorSet(epoch: ULong, set: ByteArray, pinnedHash: ByteArray) =
        inner.pinValidatorSet(epoch, set, pinnedHash)

    override fun pinnedEpochs(): List<ULong> = inner.pinnedEpochs()

    override fun verifySignature(proof: ByteArray, signature: ByteArray): VerifiedTransaction =
        inner.verifySignature(proof, signature)

    override fun verifyTransaction(proof: ByteArray): VerifiedTransaction = inner.verifyTransaction(proof)
}

/** Runs `call`, which must be refused as `case`, and returns the error. */
fun refused(what: String, case: String, call: () -> Any?): VerifyException {
    val error = try {
        call()
        error("$what: accepted")
    } catch (error: VerifyException) {
        error
    }
    val (got, detail) = describe(error)
    check(got == case) { "$what: refused as $got ($detail), not as $case" }
    println("%-28s -> %s: %s".format(what, got, detail))
    return error
}

/** Records hold byte arrays, which compare by identity, so `==` on two answers says nothing. */
fun same(a: VerifiedTransaction, b: VerifiedTransaction) =
    a.slot == b.slot && a.blockId.contentEquals(b.blockId) && a.epoch == b.epoch &&
        a.transactionId.contentEquals(b.transactionId) && a.blockTimeNanos == b.blockTimeNanos &&
        a.finality == b.finality && a.memos.size == b.memos.size &&
        a.memos.indices.all { a.memos[it].contentEquals(b.memos[it]) }

fun medianMicros(runs: Int, call: () -> Unit): Long =
    (0 until runs).map { val start = System.nanoTime(); call(); (System.nanoTime() - start) / 1000 }.sorted()[runs / 2]

fun main(arguments: Array<String>) {
    val directory = File(arguments.single())
    val expected = File(directory, "expected.txt").readLines().filter { "=" in it }
        .associate { it.substringBefore("=") to it.substringAfter("=") }
    val shredVersion = expected.getValue("shred_version").toUShort()
    val epoch = expected.getValue("epoch").toULong()
    val setHash = unhex(expected.getValue("set_hash"))
    val signature = unhex(expected.getValue("signature"))
    val memoSignature = unhex(expected.getValue("memo_signature"))
    val memos = expected.getValue("memos").split(",").filter { it.isNotEmpty() }.map(::unhex)
    val set = File(directory, "set.bin").readBytes()
    val proof = File(directory, "proof.bin").readBytes()
    val memoProof = File(directory, "memo-proof.bin").readBytes()

    val verifier = Verifier.mainnet(shredVersion)
    val through = Through(verifier)

    // Nothing is trusted yet, and the error says which epoch to pin.
    val unpinned = refused("no set pinned", "EpochNotPinned") { through.verifyTransaction(proof) }
    check((unpinned as VerifyException.EpochNotPinned).epoch == epoch)

    refused("another hash", "InvalidValidatorSet") { through.pinValidatorSet(epoch, set, ByteArray(32)) }
    refused("a hash of 31 bytes", "InvalidParameters") { through.pinValidatorSet(epoch, set, setHash.copyOf(31)) }
    check(through.pinnedEpochs().isEmpty())
    through.pinValidatorSet(epoch, set, setHash)
    check(through.pinnedEpochs() == listOf(epoch))

    // The block's first transaction.
    val verified = through.verifyTransaction(proof)
    val wanted = VerifiedTransaction(
        slot = expected.getValue("slot").toULong(),
        blockId = unhex(expected.getValue("block_id")),
        epoch = epoch,
        transactionId = signature,
        blockTimeNanos = verified.blockTimeNanos,
        finality = Finality.FAST,
        memos = emptyList(),
    )
    check(same(verified, wanted)) { "got $verified" }
    check(verified.blockTimeNanos != null)
    println("slot ${verified.slot}, epoch ${verified.epoch}, ${name(verified.finality)} finality, " +
        "block time ${verified.blockTimeNanos} ns")
    println("transaction ${verified.transactionId.hex()}")

    // One that carries a memo, asked for by its signature.
    val withMemo = through.verifySignature(memoProof, memoSignature)
    check(same(withMemo, wanted.copy(transactionId = memoSignature, memos = memos))) { "got $withMemo" }
    check(memos.isNotEmpty())
    println("${withMemo.memos.size} memo of ${withMemo.memos[0].size} bytes")

    refused("another signature", "WrongTransaction") { through.verifySignature(memoProof, signature) }
    refused("a signature of 63 bytes", "InvalidParameters") { through.verifySignature(proof, signature.copyOf(63)) }
    refused("a proof cut short", "Malformed") { through.verifyTransaction(proof.copyOf(proof.size - 1)) }
    val bent = proof.copyOf().also { it[it.size / 2] = (it[it.size / 2] + 1).toByte() }
    refused("a proof with a byte changed", "ProofRejected") { through.verifyTransaction(bent) }

    // The same keys sign on every cluster. The shred version tells their votes apart.
    Verifier.mainnet((shredVersion + 1u).toUShort()).use { elsewhere ->
        elsewhere.pinValidatorSet(epoch, set, setHash)
        refused("another cluster", "CertificateRejected") { elsewhere.verifyTransaction(proof) }
    }
    Verifier.withoutWarmup(shredVersion, 432_000uL).use { flat ->
        flat.pinValidatorSet(epoch, set, setHash)
        check(same(flat.verifyTransaction(proof), verified))
    }
    Verifier.withWarmup(shredVersion, 432_000uL).use { warm ->
        warm.pinValidatorSet(epoch, set, setHash)
        val other = refused("a schedule with warm-up", "EpochNotPinned") { warm.verifyTransaction(proof) }
        check((other as VerifyException.EpochNotPinned).epoch == epoch + 12uL)
    }
    refused("an epoch of 31 slots", "InvalidParameters") { Verifier.withoutWarmup(shredVersion, 31uL) }

    // What a call costs from the JVM, once the JIT has seen it.
    repeat(20) { verifier.verifyTransaction(proof) }
    val verifyMicros = medianMicros(100) { verifier.verifyTransaction(proof) }
    val pinMicros = medianMicros(20) { Verifier.mainnet(shredVersion).use { it.pinValidatorSet(epoch, set, setHash) } }
    println("verify with the set kept: median $verifyMicros us; pin a set of ${(set.size - 4) / 56} validators: " +
        "median $pinMicros us")

    // Forgetting takes the trust away again.
    through.pinValidatorSet(epoch - 1uL, set, setHash)
    check(through.forgetEpochsBefore(epoch) == 1uL)
    check(through.forgetEpoch(epoch))
    check(!through.forgetEpoch(epoch))
    check(through.pinnedEpochs().isEmpty())
    refused("the epoch forgotten", "EpochNotPinned") { through.verifyTransaction(proof) }

    verifier.close()
    println("OK")
}
