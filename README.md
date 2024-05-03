# `thunderdup` - Fast concurrent linux file deduplicator

**How to use:**
```console
$ time thunderdup
Scanning ...
2024-05-03 06:58:10:
	unique:    276	173 MiB
	duplicate: 2	213 KiB
	queue length: 0
	currently working workers: 0/192
Deduplicating ...
deduplicating: docs/examples/example-folder/ipfs.paper.draft3.pdf
	- docs/examples/example-folder/test-dir/ipfs.paper.draft3.pdf
deduplicating: .git/hooks/pre-rebase.sample
	- test/sharness/lib/sharness/.git/hooks/pre-rebase.sample
total dedupped: 426 KiB
dedupping errors: 0

________________________________________________________
Executed in   73.64 millis    fish           external
   usr time  179.56 millis  621.00 micros  178.94 millis
   sys time   83.87 millis   80.00 micros   83.79 millis
```

This is a non incremental file deduplicator, tested on btrfs.

# How to install

## With `go` installed

```bash
go install github.com/Jorropo/thunderdup@latest
```

Or run as a one shot script:
```bash
go run github.com/Jorropo/thunderdup@latest
```

# `thunderdup` vs `bees`

I was using [`bees`](https://github.com/Zygo/bees) but it wasn't fitting my usecase very well.

Advantages over `bees`:
- Faster (reliable 4GiB/s on my Ryzen 3600 with raid1 × 2 NVME).
- Written in a memory safe language (*hopefully never matter*).
- Easier to use (just go to the directory and run it).
- More granular dedup (dedup selected files or directories recursively instead of whole filesystem)
- File based dedup, does not shard or move extants around on disk,
  - less fragmentation compared to block based dedup
  - less wear on SSDs.
  - \*shouldn't be undeduped by `btrs fi defrag`.
- *Perfect* deduplication, no probabilistic hash table that lead to partial deduplication of data.

Disadvantages over `bees`:
- Unbounded memory use, `bees` use a probabilistic hash table which let it to use a fixed amount of memory at the cost of deduping accuracy, `thunderdup` stores all the files scanned and their hash in memory, it will crash if you have too much files compared to your amount of ram.
- Non incremental, require full scan on each time, more realistically this is usefull as a one shot tool.
- Less to none workarounds for kernel btrfs bugs. I didn't got any issue on my Linux 6.8.8 and 6.1.0 installs but this is very likely less stable than `bees` on previous kernels.
- File based dedup, `bees` can dedup files which only have partial overlaps.

\*needs investigation to make sure this doesn't work by accident, I tried it once and it worked properly.

# Q&A

## Is it safe ?

`thunderdup` is written in a memory safe language (Go) and open all the files in Read-Only mode, deduplication happens using linux's `FileDedupeRange` syscall which atomically compare file content in the kernel.

**Assuming there are no bugs in the kernel**, the worst that can happen is dedup not happening where it should have, it can't corrupt or change the content of your files.

It is also possible to have a bug in Go or thunderdup itself, but that less likely.