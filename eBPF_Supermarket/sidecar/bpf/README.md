# BPF

## Intro

This directory is all about BPF programs and management. It includes:

- [TCP Accept Event Probe](tcpaccept): captures TCP accept event information. With time, pid, address and port information.
- [TCP Connect Event Probe](tcpconnect): captures TCP connect event information. With time, pid, address and port information.
- [TCP Close Event Probe](tcpclose): captures TCP close event information. With basic info and traffic statistics.
- [Network Subsystem Probe](podnet): traces key network event in host, for most scenarios in this project, in-pod network stack.

For most probes, they can filter by process id, and notify you by Go channel.

## BFP Develop Guide

1. Define event struct for both C and Go. For network tracing, maybe you have to provide both IPv4 and IPv6 versions.
2. Write your tracing code by C, which must match the argument list.
3. Insert filter policy code dynamically. Filtering by pid is the most frequently used policy.
4. Attach your code to instrumentation point.
5. Initialize your event map, and got its Go channel.
6. Start a goroutine and wait for event to happen.
7. Process the event struct to user-friendly format and submit to the upper caller.

## Hints

To develop BPF program in Go, here are some best practices hints. Maybe they are useful for you.

1. Keep your event struct *aligned in 8 byte*. Compiler always do some unknowable things when we write not aligned code. For some time, the compiler of C and the compiler of Go organize your struct differently. And, when you read binary data from C to Go, they will come out and make trouble. So, keep your data structure aligned to avoid it.
2. Use `/*FILTER*/` as placeholder for inserting filter code. That can make sure your code can work even if you don't provide filter code.
3. In [iovisor/bcc@ffff0ed](https://github.com/iovisor/bcc/commit/ffff0edc00ad249cffbf44d855b15020cc968536), `bcc_func_load`'s signature was changed. However, [gobpf](https://github.com/iovisor/gobpf) still lacks of maintenance on this. So, we should change the library as [this PR](https://github.com/iovisor/gobpf/pull/311). As a workaround, we extracted this as a [new library](https://github.com/ESWZY/gobpf/tree/0.24.0), and just need use `replace` directive `replace github.com/iovisor/gobpf => github.com/ESWZY/gobpf v0.2.1-0.20220720201619-9eb793319a76` in `go.mod` file (after `go get github.com/ESWZY/gobpf@0.24.0`).

## See Also

[BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)

[eBPF Mistake Avoidance Guide (blog in Chinese)](https://segmentfault.com/a/1190000041179276)
