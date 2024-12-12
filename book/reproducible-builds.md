# Reproducible Builds

## Overview

When deploying SP1 Blobstream in production, it's important to ensure that the program used when generating proofs is reproducible.

## Prerequisites

You first need to install the [cargo prove](https://docs.succinct.xyz/getting-started/install.html#option-1-prebuilt-binaries-recommended) toolchain.

Ensure that you have the latest version of the toolchain by running:

```bash
sp1up
```

Confirm that you have the toolchain installed by running:

```bash
cargo prove --version
```

## Verify the SP1 Blobstream binary

To build the SP1 Blobstream binary, first ensure that Docker is running.

```bash
docker ps
```

Then build the binaries:

```bash
cd program

# Builds the SP1 Blobstream binary using the corresponding Docker tag, output directory and ELF name.
cargo prove build --docker --tag v3.0.0 --output-directory ../script --elf-name blobstream-elf
```

Now, verify the binaries by confirming the output of `vkey` matches the vkeys on the contract. The `vkey` program outputs the verification key
based on the ELF in `/elf`.

```bash
cargo run --bin vkey --release
```
