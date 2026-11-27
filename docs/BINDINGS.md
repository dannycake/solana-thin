# Bindings

The verifier is a Rust crate. This is how it gets into a Kotlin, Swift or
JavaScript program, what that costs, and what has and has not been run.

| Crate | What it is |
|---|---|
| `crates/solana-thin-ffi` | The binding for Kotlin and Swift, generated with [UniFFI](https://mozilla.github.io/uniffi-rs/) 0.32. Builds as a shared library (Android, JVM) and a static one (iOS). |
| `crates/uniffi-bindgen` | UniFFI's generator at the same release, and `describe-interface`, which lists what a built library exports. |
| `crates/solana-thin-wasm` | The verifier as a WebAssembly module with no imports, and `solana-thin.mjs`, a class around it. Published to npm as `solana-thin`. |

The WebAssembly module is published to npm as
[`solana-thin`](https://www.npmjs.com/package/solana-thin), and the Swift
binding as a Swift package (this repository, resolved by a version tag; see
"iOS and the simulator" below). The Kotlin/Android binding is not published to
a registry: build the library and generate the sources as below.

## The interface

It is the same in every language, up to each one's spelling. The exact list
is [`crates/solana-thin-ffi/interface.txt`](../crates/solana-thin-ffi/interface.txt),
which is checked against the built library.

- **`Verifier`**, made for one cluster by `mainnet(shredVersion)`,
  `withoutWarmup(shredVersion, slotsPerEpoch)` or
  `withWarmup(shredVersion, slotsPerEpoch)`. It trusts nothing at first, keeps
  no chain state and makes no network calls. It can be shared between threads.
- **`pinValidatorSet(epoch, set, pinnedHash)`** trusts a validator set for an
  epoch if it hashes to the 32-byte hash. The hash is your trust root. The
  epoch is your word too: nothing about it is read from the set or from any
  proof. The hash is compared before any key is checked.
- **`pinnedEpochs()`**, **`forgetEpoch(epoch)`**, **`forgetEpochsBefore(epoch)`**
  list and drop what is trusted.
- **`verifyTransaction(proof)`** checks a proof and says which transaction it
  is for. **`verifySignature(proof, signature)`** also checks that it is for
  the transaction with that 64-byte id.
- The answer, **`VerifiedTransaction`**: `slot`, `blockId`, `epoch` (of the
  validator set that vouched), `transactionId`, `blockTimeNanos` (absent when
  the proof does not open the block's footer), `finality` (fast or slow) and
  `memos`.
- A refusal, **`VerifyError`**: one case per kind of
  [`ErrorKind`](../crates/solana-thin/src/error.rs), whose table says what
  each means for an app, with the verifier's sentence in `detail`.
  `EpochNotPinned` also carries the epoch to pin. Match on the case, never on
  the text.

A successful answer means what the README says it means, and no more: the
transaction is in a finalized block, not that it succeeded.

**Keep the verifier.** Pinning a set checks every key in it and takes tens of
milliseconds (hundreds in WebAssembly). Checking a proof against a pinned set
takes about one millisecond (seven in WebAssembly). Make one verifier when
the app starts and reuse it.

**Threads.** `blst` would start a thread pool the first time a signature is
checked. `solana-thin-ffi` turns that off by default (its `no-threads`
feature), so a call does its work on the thread that made it. Cargo features
can only add, so the way to let `blst` use its pool is
`--no-default-features`. The measured difference on a desktop is about a
tenth of a millisecond per proof.

## Android

You need the Android NDK and the Rust targets:

```sh
rustup target add aarch64-linux-android x86_64-linux-android
```

Point cargo at the NDK's clang, which compiles `blst` and links the library.
`24` is the lowest Android API level the library will load on:

```sh
bin=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin   # darwin-x86_64 on a Mac
export CC_aarch64_linux_android=$bin/aarch64-linux-android24-clang
export AR_aarch64_linux_android=$bin/llvm-ar
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$bin/aarch64-linux-android24-clang
cargo build -p solana-thin-ffi --release --target aarch64-linux-android
```

For an x86-64 emulator image, set the same three variables for
`x86_64-linux-android` and add `--features portable`: without it `blst` is
built for the CPU of the build machine and may stop with an illegal
instruction on another.

Generate the Kotlin source from the library, with the generator in this
workspace so that both come from one UniFFI release:

```sh
cargo run -p uniffi-bindgen -- generate --language kotlin --out-dir <your source set> \
  target/aarch64-linux-android/release/libsolana_thin_ffi.so
```

That writes `uniffi/solana_thin_ffi/solana_thin_ffi.kt`. In the app:

- put the library at `src/main/jniLibs/arm64-v8a/libsolana_thin_ffi.so`
  (`x86_64/` for the emulator build);
- depend on JNA as an Android archive: `net.java.dev.jna:jna:<version>@aar`.

```kotlin
import uniffi.solana_thin_ffi.Verifier
import uniffi.solana_thin_ffi.VerifyException

val verifier = Verifier.mainnet(50093u)
verifier.pinValidatorSet(1095uL, setBytes, pinnedHash)

try {
    val tx = verifier.verifySignature(proofBytes, mySignature)
    println("final in slot ${tx.slot}, ${tx.memos.size} memos")
} catch (e: VerifyException.EpochNotPinned) {
    // e.epoch is the epoch whose set to fetch and pin, then check again.
} catch (e: VerifyException) {
    // Not shown to be final. e.message has the case's fields.
}
```

Byte arrays in a Kotlin record compare by identity, so `==` on two answers is
false even when they are equal. Compare the fields.

Built with NDK r30, the library's segments are aligned to 16 KiB, as devices
with 16 KiB pages need.

## iOS and the simulator

*All five steps were run with this crate on an Apple silicon Mac (macOS 27.0,
Xcode 27.0 with Swift 6.4 and the iOS 27.0 SDK): steps 1 to 4 and the phone
on 2026-11-25, and step 5, the simulator, rerun with this crate on
2026-11-26. The generated Swift compiled and the package's tests passed both
on the macOS slice and on a booted iOS 27 simulator.*

You need an Apple silicon Mac with Xcode (not only the Command Line Tools)
and one iOS simulator runtime. `xcode-select -p` must print a path inside
Xcode. No Apple developer account and no phone are needed up to the
simulator. Then:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
export IPHONEOS_DEPLOYMENT_TARGET=15.0     # the oldest iOS to support; blst's C is built for it too
unset MACOSX_DEPLOYMENT_TARGET             # see "Traps"
```

**1. The library**, once per target, as a static library:

```sh
for target in aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin; do
  cargo build -p solana-thin-ffi --release --target $target
done
```

Nothing else is needed: the `cc` crate finds the iOS SDK through `xcrun` and
builds `blst`'s C and assembly for each target.

**2. The Swift source**, generated from the library:

```sh
cargo run --release -p uniffi-bindgen -- generate --language swift --out-dir out/gen \
  target/aarch64-apple-ios/release/libsolana_thin_ffi.a
```

That writes `solana_thin_ffi.swift`, `solana_thin_ffiFFI.h` and
`solana_thin_ffiFFI.modulemap`. The Swift file goes into your sources. The
header and the module map go into a folder named after the module, with the
map renamed to `module.modulemap`, the only name clang looks for:

```
out/headers/solana_thin_ffiFFI/solana_thin_ffiFFI.h
out/headers/solana_thin_ffiFFI/module.modulemap
```

**3. An XCFramework** from the three static libraries:

```sh
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libsolana_thin_ffi.a     -headers out/headers \
  -library target/aarch64-apple-ios-sim/release/libsolana_thin_ffi.a -headers out/headers \
  -library target/aarch64-apple-darwin/release/libsolana_thin_ffi.a  -headers out/headers \
  -output solana_thin_ffiFFI.xcframework
```

**4. A Swift package** around it needs no Xcode project:

```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SolanaThin",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [.library(name: "SolanaThin", targets: ["SolanaThin"])],
    targets: [
        .binaryTarget(name: "solana_thin_ffiFFI", path: "solana_thin_ffiFFI.xcframework"),
        // Sources/SolanaThin/solana_thin_ffi.swift, as generated.
        .target(name: "SolanaThin", dependencies: ["solana_thin_ffiFFI"]),
        .testTarget(name: "SolanaThinTests", dependencies: ["SolanaThin"], resources: [.copy("vectors")]),
    ]
)
```

```swift
import SolanaThin

let verifier = Verifier.mainnet(shredVersion: 50093)
try verifier.pinValidatorSet(epoch: 1095, set: setBytes, pinnedHash: pinnedHash)

do {
    let tx = try verifier.verifySignature(proof: proofBytes, signature: mySignature)
    print("final in slot \(tx.slot), \(tx.memos.count) memos")
} catch VerifyError.EpochNotPinned(_, let epoch) {
    // `epoch` is the epoch whose set to fetch and pin, then check again.
} catch {
    // Not shown to be final.
}
```

`swift test` in the package runs its tests on the Mac against the
XCFramework's macOS slice, so the Swift side can be worked on without a
simulator. A caller can also be compiled with `swiftc` alone, against one
slice:

```sh
X=solana_thin_ffiFFI.xcframework
swiftc -O -target arm64-apple-ios15.0-simulator -sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)" \
  -I $X/ios-arm64-simulator/Headers -L $X/ios-arm64-simulator -lsolana_thin_ffi -Xlinker -dead_strip \
  Sources/SolanaThin/solana_thin_ffi.swift main.swift -o verify-proof-sim
```

**5. The tests in the simulator.** Make one, run the package's tests in it,
delete it:

```sh
SIM=$(xcrun simctl create solana-thin-tests "iPhone 17")
xcrun simctl boot "$SIM" && xcrun simctl bootstatus "$SIM" -b
xcodebuild test -scheme SolanaThin -destination "platform=iOS Simulator,id=$SIM" \
  -derivedDataPath ../derived CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual
xcrun simctl shutdown "$SIM" && xcrun simctl delete "$SIM"
```

### Traps

- **Do not set `MACOSX_DEPLOYMENT_TARGET` to 12.0 or later for the Rust
  build.** With it set, a release build fails with `can't find crate for
  zeroize_derive`: rustc strips the procedural-macro library it has just
  linked, and the loader then refuses it ("mis-aligned LINKEDIT string
  pool"). Seen with Rust 1.94.0, Xcode 27.0 and macOS 27.0. Debug builds, and
  builds with the variable unset, are fine.
- **A dynamic library for iOS may hit the same refusal**, since rustc strips
  it the same way. Not tested: the XCFramework carries static libraries,
  which rustc does not strip. If a dynamic framework is wanted, try `-C
  strip=none -C link-arg=-Wl,-x -C link-arg=-Wl,-S`.
- **The simulator slice is arm64 only.** A build for `generic/platform=iOS
  Simulator` also links for x86-64 and fails with undefined symbols. Name one
  simulator in `-destination`. An Intel Mac would need `x86_64-apple-ios`
  built too and joined to the simulator library with `lipo` (not run).
- **If `xcodebuild test` stops at `GatherProvisioningInputs`**, the Mac's
  keychain service is not answering. Pass `CODE_SIGNING_ALLOWED=NO` in place
  of the two signing settings: the linker's own ad hoc signature is all the
  simulator needs for these tests.
- **A simulator that has just been created is busy for a few minutes.**
  Timings taken straight after its first start had medians about twice the
  minimums. After 150 seconds they matched the Mac's own.
- `swiftc` for an iOS target warns that it is `using sysroot for 'macOS
  27.0'`. The output is still built for iOS (`otool -l` shows platform 2, or
  7 for the simulator).

### On a phone

Run on 2026-11-25 on an iPhone 17 Pro with iOS 27.2.1: the tests above, in
a test bundle hosted by an app that does nothing else, verified the proofs
of all 331 transactions of mainnet slot 473,100,911 against the exact set of
epoch 1095, a proof built that day for a transaction of epoch 1097 against
the set fixed the day before, and got the expected error for a changed
proof, a set that is not the pinned one, another cluster's shred version and
an epoch with no set. Timings are under "What it costs".

It needs an Apple developer team (a free personal team works) with its
development certificate in an unlocked keychain, a bundle identifier the
team can use, the phone paired with Developer Mode on, and the phone
unlocked while the tests run.

The package's own tests cannot run on a phone: `xcodebuild test` on a device
destination refuses with "Tool-hosted testing is unavailable on device
destinations". The tests need a host app. With XcodeGen, a `project.yml`
beside the package:

```yaml
name: SolanaThinCheck
options:
  bundleIdPrefix: <your prefix>
  deploymentTarget: { iOS: "15.0" }
settings:
  base: { DEVELOPMENT_TEAM: <team id>, CODE_SIGN_STYLE: Automatic }
packages:
  SolanaThin: { path: ../SolanaThin }
targets:
  SolanaThinCheck:                      # App/App.swift: an empty SwiftUI app
    type: application
    platform: iOS
    sources: [App]
    dependencies: [{ package: SolanaThin }]
    settings:
      base: { GENERATE_INFOPLIST_FILE: YES, INFOPLIST_KEY_UILaunchScreen_Generation: YES }
  SolanaThinCheckTests:
    type: bundle.unit-test
    platform: iOS
    sources:
      - Tests                           # the tests, reading Bundle(for:) instead of Bundle.module
      - { path: ../SolanaThin/Tests/SolanaThinTests/vectors, type: folder, buildPhase: resources }
    dependencies: [{ target: SolanaThinCheck }, { package: SolanaThin }]
    settings:
      base:
        GENERATE_INFOPLIST_FILE: YES
        TEST_HOST: "$(BUILT_PRODUCTS_DIR)/SolanaThinCheck.app/SolanaThinCheck"
        BUNDLE_LOADER: "$(TEST_HOST)"
schemes:
  SolanaThinCheck:
    build: { targets: { SolanaThinCheck: all, SolanaThinCheckTests: [test] } }
    test: { targets: [SolanaThinCheckTests] }
```

```sh
xcodegen generate
xcrun devicectl list devices            # the phone's identifier
xcodebuild test -project SolanaThinCheck.xcodeproj -scheme SolanaThinCheck \
  -destination id=<identifier> -allowProvisioningUpdates -allowProvisioningDeviceRegistration
```

## WebAssembly

The verifier needs no change to build for `wasm32-unknown-unknown`: depend on
`solana-thin` from your own crate and build it with a clang that can compile
for wasm32, because `blst` is C. `blst` has no threads there, and uses its C
in place of its assembly.

`crates/solana-thin-wasm` is the smallest complete example. It exports six C
functions and imports nothing, so no `wasm-bindgen` and no bundler are
involved:

```sh
rustup target add wasm32-unknown-unknown
cargo build -p solana-thin-wasm --release --target wasm32-unknown-unknown
# target/wasm32-unknown-unknown/release/solana_thin_wasm.wasm
```

`crates/solana-thin-wasm/solana-thin.mjs` wraps the module in a class. It is
plain ECMAScript and runs in node and in a browser as it is:

```js
import { load, VerifyError } from './solana-thin.mjs';

const { Verifier } = await load(bytesOfTheWasmFile);
const verifier = Verifier.mainnet(50093);
verifier.pin(1095n, setBytes, pinnedHash);

try {
  const tx = verifier.verify(proofBytes, mySignature);
  console.log(`final in slot ${tx.slot}, ${tx.memos.length} memos`);
} catch (error) {
  if (!(error instanceof VerifyError)) throw error;
  // error.kind is an ErrorKind name; with EpochNotPinned, error.epoch says which to pin.
}
```

Slots, epochs and times are `BigInt`: a block time in nanoseconds does not
fit a JavaScript number. Bytes are `Uint8Array`. Call `free()` on a verifier
you are done with; the module's memory is not garbage-collected.

The JavaScript answer carries more than the Kotlin and Swift one: also the
block's `parent`, the block the certificate was for (`finalizedBy`), the
transaction's `position` in its batch, the `footer`'s bank hash and the
leader's client string, and the `transaction` as the verifier read it
(signatures, account keys, recent blockhash, instructions, message bytes).
`solana-thin.d.ts` types them all. [explorer/](../explorer/README.md) is a
web page built on this.

`scripts/wasm.sh` builds all of this and verifies a mainnet proof under node.
`scripts/wasi-test.sh` runs the verifier's own test suite as a
`wasm32-wasip1` program under node's WASI.

## What it costs

Measured on 2026-11-25. "Desktop" is a 12th-generation Intel Core desktop CPU
running Linux, with Rust 1.99.1; "Mac" is the Apple silicon Mac described
under iOS. The validator set is mainnet's for epoch 1095, 666 validators in
37,300 bytes. Times are medians; the phone's are over its 331 transactions.
The iOS-simulator row was confirmed with this crate on 2026-11-26.

| Where | Pin a set | Verify, set kept |
|---|---|---|
| Kotlin on the JVM (OpenJDK 21, JNA), desktop | 30 ms | 1.1 ms |
| WebAssembly under node 26 (V8), desktop | 174 ms | 7.3 ms |
| Swift on the Mac | 32 ms | 1.2 ms |
| Swift in the iOS simulator on the Mac | 32 ms | 1.2 ms |
| Swift on an iPhone 17 Pro, iOS 27.2.1 | 21 ms | 0.82 ms (95th percentile 0.96 ms) |

On the phone a new verifier, pinning the set and checking one proof took a
median 21 ms in all.

Three quarters of pinning is the subgroup check of each key, and nearly all
of verifying is checking the certificate's signature. Proof size hardly
matters: a 64 KB proof took at most 0.3 ms longer than a 3 KB one.

| Artifact, release profile | Bytes | Stripped |
|---|---|---|
| `libsolana_thin_ffi.so`, Android arm64 (NDK r30) | 915,816 | 637,560 |
| `libsolana_thin_ffi.so`, Android x86-64, `portable` | 932,816 | 734,392 |
| `libsolana_thin_ffi.so`, Linux x86-64 | 906,656 | 683,704 |
| `solana_thin_wasm.wasm` | 239,528 | 81,963 gzipped |
| `libsolana_thin_ffi.a`, iOS arm64 (prototype) | 18,472,320 | |
| What that adds to a linked Swift executable (prototype) | about 560,000 | |

A static library carries everything the linker might want; what an app gains
is the last row. The WebAssembly module's memory stood at 1,472 KiB after the
checks.

Dependencies, as `cargo tree -e normal,build` counts packages for one target:
23 for `solana-thin`, 58 for `solana-thin-ffi`, 75 for the generator. UniFFI
is taken without its `cargo-metadata` feature, which only the generator
needs. UniFFI is MPL-2.0; everything else is MIT, Apache-2.0 or Unicode-3.0.

Compilers: `solana-thin-ffi` and `solana-thin-wasm` build on Rust 1.85, like
the verifier. The generator follows stable (1.91 at the locked versions).

## What was run where

| Where | What | State |
|---|---|---|
| Linux x86-64 | Every Rust test in the workspace. The binding through generated Kotlin on the JVM. The WebAssembly module under node. The verifier's test suite under WASI. | This revision. CI repeats it on every push |
| Android arm64 and x86-64 | The library builds and links with the NDK for both. The x86-64 binding, through generated Kotlin and JNA, verifies a mainnet proof in an instrumented test. | Both built; x86-64 run on an emulator (maps-36, Android 36), 2026-11-26. By hand, not in CI |
| macOS arm64 | The library, the XCFramework, and the Swift package's tests, which verify a mainnet proof. | This revision, 2026-11-26 |
| iOS simulator, arm64 | The Swift package's tests, with this crate, on a booted simulator. | This revision, 2026-11-26. By hand, not in CI |
| iOS, an iPhone 17 Pro | The tests in a hosted test bundle: 331 of 331 mainnet proofs, one from epoch 1097, four refusals. | 2026-11-25. By hand, not in CI |
| A browser | The WebAssembly module, verifying a mainnet proof. | Headless Chromium, 2026-11-26. By hand, not in CI |
| Android, a phone | Nothing. The emulator above stands in for it. | Never run on physical hardware |

## Checking the bindings

```sh
scripts/bindings.sh    # the exported interface, generation, the Kotlin smoke test
scripts/wasm.sh        # the module, and a mainnet proof under node
scripts/wasi-test.sh   # the verifier's tests under WASI; a few minutes
```

`scripts/bindings.sh` builds the library for the machine it runs on and:

1. lists the interface the library exports (`describe-interface`) and compares
   it with `crates/solana-thin-ffi/interface.txt`. A change to what foreign
   callers see is a change to that file; `--update` rewrites it.
2. generates the Kotlin and Swift sources under `target/bindings/`. They are
   not in the repository: they follow from the library and the UniFFI
   release, and a stale copy would be worse than none.
3. compiles `crates/solana-thin-ffi/kotlin/Smoke.kt` with them and runs it on
   the JVM, where it verifies a mainnet proof and checks each refusal. The
   smoke test names every error case, method and record field, so it stops
   compiling when the Rust side changes under it. This step needs a JDK and
   `kotlinc`, and is skipped with a message without them unless
   `--require-jvm` is given, as it is in CI. JNA is downloaded from Maven
   Central and checked against a pinned hash, or taken from `JNA_JAR`.

These scripts do not compile the generated Swift. That is checked on a Mac,
where `swift test` builds the package against the macOS slice and
`xcodebuild test` runs it on an iOS simulator; see "iOS and the simulator".
