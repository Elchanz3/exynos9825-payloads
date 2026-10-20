# Replicating the custom-key chain on a second board

What this does: makes a SM-N975F verify its bootloader against **our** key
instead of Samsung's, permanently, so it boots a chain we sign.

What it costs: the board's KEY2 slot and its USE_KEY2 bit are one-way fuses.
After step 5 the board accepts nothing signed by anyone else, for the rest of
its life. Losing `keys/4/st1.pem` + `keys/hmac.bin` makes it unbootable with
no software recovery.

The procedure below is the one that worked, reordered with hindsight: the
original run took three Odin flashes and hit an AVB error, because
`keystorage.bin` was left stale. One combined BL tar removes both problems.

## Before starting

- The board must be on **N975FXXS9HWG3**, the firmware the resigned chain was
  built from. Put it there with a normal full Odin flash first.
- EUB entry works. It is needed twice, and it is the only way back in if a
  step goes wrong.
- `keys/4/st1.pem` and `keys/hmac.bin` are backed up somewhere off this
  machine. Verify with `9825_customkey/backup_keys.sh`, which re-derives the
  anchor and refuses if it does not match.

## 1. Build the artifacts

```sh
cd /home/chanz22/Documents/GitHub/exynos9825-payloads

# our cm.bin and our keystorage.bin, re-signed with our ST2-TEE key
python3 tools/make_custom_cm.py
python3 tools/resign_st2_container.py \
    <(tar xOf $FW/BL_*.tar.md5 keystorage.bin.lz4 | lz4 -d -c) \
    build/custom_keystorage/keystorage.bin

# one BL tar: our sboot, our cm, our keystorage, Samsung's uh/param/up_param/vbmeta
MODE=full ./tools/build_partial_bl_tar.sh \
    $PWD/build/partial_bl/BL_ours_full.tar.md5

# the two fuse chains
./tools/build_key2_fuse_chain.sh program-streamed
./tools/build_key2_fuse_chain.sh use-streamed
```

## 2. Flash the whole bootloader chain, ours included

```sh
sudo odin4 -b /home/chanz22/Documents/GitHub/exynos9825-payloads/build/partial_bl/BL_ours_full.tar.md5
```

**The board stops cold-booting here.** That is correct: our anchor is on the
board but not yet in the fuse, so the BootROM rejects our sboot. From this
point until step 5 the only way in is EUB.

Doing it in one tar matters. Flashing our `cm.bin` under a stock `sboot`
produces a board that does not boot either, for a different reason -- the
stock chain verifies the LDFW against Samsung's key -- and leaves you
debugging two failures at once.

## 3. Program KEY2

```sh
./tools/run_key2_program_streamed.sh          # asks for: burn key2
/home/chanz22/EUB-N10/9825_customkey/run_key_dump_test.sh
```

Expect `KEY2 = 1d12d364cf441dfe7d5084a054691cf1c7f71e068e2470881e52ce280c7c330b`.

Irreversible, but it commits nothing: `0x16` writes the slot and sets no SEC
bit, measured. The board behaves exactly as before.

**Stop here if the read-back does not match.** Everything after assumes it.

## 4. Confirm nothing was committed

```sh
/home/chanz22/EUB-N10/9825_customkey/run_key_state_test.sh
```

Expect `SEC0 = 0x00000001`, predicates `C=0 D=0 E=1`, selector picking
`0x10003000`.

## 5. Set USE_KEY2

```sh
./tools/run_key2_use_streamed.sh              # asks twice, ends in: commit to key2
/home/chanz22/EUB-N10/9825_customkey/run_key_state_test.sh
```

Expect `SEC0 = 0x00000003`, `C=1`, selector picking `0x10003020`, pointer
agreeing.

**This is the point of no return.** Cold-boot the board now: it should come
up on our bootloader, into Download mode with the engineering flags.

## 6. Put Android back

```sh
sudo odin4 \
  -a $FW/AP_*.tar.md5 \
  -c $FW/CP_*.tar.md5 \
  -s $FW/HOME_CSC_*.tar.md5 \
  --reboot
```

No `-b`: the BL from step 2 is already correct and must not be overwritten
with Samsung's. `HOME_CSC` rather than `CSC` because `CSC` carries the PIT
and there is no reason to repartition.

`userdata.img` is inside AP, so the data goes.

## If something fails

| symptom | cause | fix |
|---|---|---|
| no cold boot between steps 2 and 5 | expected | continue; EUB is the way in |
| `0x16` read-back blank | LDFW did not come up | our `cm.bin` must be on CM; step 2 does that |
| AVB "public key used to sign data (2)" | stale `keystorage.bin` | step 2 ships ours; check it was not overwritten by a BL flash |
| black after step 5 | our chain rejected from UFS | EUB still works; `0x18` BAN_KEY2 is the untested escape |

`0x18` restores the KEY path by setting `D`, on the inference that `C`/`D`
are the USE/BAN pair. `C` was measured; `D` never has been. `E` stays `1`, so
if `D` does what it should, Samsung's key comes back.
