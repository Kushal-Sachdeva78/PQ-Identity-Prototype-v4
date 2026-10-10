# Contributing to the PQ-Identity setup ceremony

This sheet travels with the kit. The coordinator sends you a folder or zip.

## What you are doing

- You add your own randomness to the proving key of a zero-knowledge circuit.
- The final key is safe if at least one contributor's randomness stays secret. Yours is made
  on your computer by the operating system's random generator, kept in memory, and never saved.
- You send back the new key file and a small receipt. Nothing you send is secret.

## What you need

- Windows, macOS or Linux; Node.js 20 or newer (LTS from https://nodejs.org).
- Internet once, for `npm install` (it installs snarkjs 0.7.4 into the kit folder only).
- About 15 MB of disk (plus about 38 MB if the kit includes the verification files).
- A few minutes. The contribution itself takes seconds; the optional check takes longer.

## Steps

1. Unzip the kit into a new folder and open a terminal there
   (Windows: PowerShell; macOS: Terminal; Linux: any shell).
2. Check the files against `SHA256SUMS.txt`:
   - Windows: `Get-FileHash -Algorithm SHA256 .\*` and compare by eye.
   - macOS: `shasum -a 256 -c SHA256SUMS.txt`
   - Linux: `sha256sum -c SHA256SUMS.txt`
3. The coordinator also sent you, by a second route (message, email or in person), the SHA-256 of
   the input `.zkey`. Keep it for step 5.
4. Install snarkjs into the kit folder: `npm install` (Windows PowerShell: `npm.cmd install`, because
   PowerShell may block the `npm.ps1` shim)
5. Run the script. Use the file names from your kit; `<hex>` is the value from step 3.
   - Windows:
     ```
     powershell -NoProfile -ExecutionPolicy Bypass -File .\contribute.ps1 -InputZkey .\credential_auth_v4_000N.zkey -Name "Your Name" -OutputZkey .\credential_auth_v4_000M.zkey -ExpectInputSha256 <hex>
     ```
   - macOS / Linux:
     ```
     bash contribute.sh credential_auth_v4_000N.zkey "Your Name" credential_auth_v4_000M.zkey --expect-sha256 <hex>
     ```
   - If the kit has `credential_auth_v4.r1cs` and a `.ptau` file, add
     `-R1cs .\credential_auth_v4.r1cs -Ptau .\powersOfTau28_hez_final_15.ptau` (Windows) or
     `--r1cs credential_auth_v4.r1cs --ptau powersOfTau28_hez_final_15.ptau` (macOS/Linux).
     The script then checks your output before you send it.
   - Optional: `-ExtraEntropy` / `--extra-entropy` asks you to type random text as well
     (hidden, never saved). The OS randomness alone is enough.
6. The script prints `CONTRIBUTION_HASH <128 hex characters>`. Copy that line.
7. Send back the output `.zkey` and its `.receipt.json` (the receipt has your name, file hashes,
   software versions and OS type; no secrets, no computer or user name).
8. Send the `CONTRIBUTION_HASH` line by a different route than the files, or post it publicly
   yourself. This lets you check later that the published transcript lists exactly your hash.

## Rules

- The name you give appears in the key file and the public transcript. Use the name or handle
  you want to be public.
- One contribution per person. If a step fails, send nothing and tell the coordinator.
- Do not edit the scripts or the `.zkey` files. If you want to read the scripts first, please do:
  `contribute.ps1`, `contribute.sh`, `contribute_core.mjs` and `lib.mjs` are short.
- `-ExecutionPolicy Bypass` affects only that one PowerShell process; it changes no setting.

## After the ceremony

- The coordinator publishes a transcript listing every contribution hash in order, the public
  beacon and the final key's hash. Check that your hash is there under your name.
- With the final files you can check everything yourself:
  `node coordinator.mjs audit --transcript ceremony_transcript.json --zkey credential_auth_v4_final.zkey --r1cs credential_auth_v4.r1cs --ptau powersOfTau28_hez_final_15.ptau --my-hash <your hash>`
  (`coordinator.mjs` comes with the kit; run `npm install` in the kit folder first.)
