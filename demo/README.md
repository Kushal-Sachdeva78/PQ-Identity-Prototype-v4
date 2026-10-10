# Offline v4 demo (TASKS G)

- Live: `npx tsx demo/v4_demo.ts` (about 10 to 15 s; everything local: Anvil on 127.0.0.1,
  no network). `--pace 12` waits 12 s between steps for a talk. The key is the dev key.
- Steps: set-up (governance, issuer, verifier), two credentials, adult accepted, minor's honest
  wallet refuses, malicious wallet with a forged birth date fails the circuit, replay rejected,
  revocation then no presentation.
- Recorded fallback: `python demo/record_mp4.py` renders `demo/out/transcript.txt` (written by
  the live run) as `demo/v4_demo_fallback.mp4` (1280x720, H.264, needs ffmpeg). The screen shows
  program output only, no timings (performance numbers come from Phase D) and no names.
- Slides and the spoken script are the author's.
