# MEM_WRITE_WATCH

[VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) has a `MEM_WRITE_WATCH` flag that allows you to track when pages are written to. MSDN has this to say about it:

> **MEM_WRITE_WATCH** 0x00200000
>
> Causes the system to track pages that are written to in the allocated region. If you specify this value, you must also specify **MEM_RESERVE**.
>
> To retrieve the addresses of the pages that have been written to since the region was allocated or the write-tracking state was reset, call the [GetWriteWatch](https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-getwritewatch) function. To reset the write-tracking state, call GetWriteWatch or [ResetWriteWatch](https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-resetwritewatch). The write-tracking feature remains enabled for the memory region until the region is freed.

Internally this is implemented as a kind of shadow-bitmap of page dirty bits, with some additional logic glued in between. You can read my reverse engineered source [here](MEM_WRITE_WATCH_internals.c).

When you call `VirtualAlloc` it goes through to `NtAllocateVirtualMemory`, which then calls into `MiAllocateVirtualMemory` using an opaque struct that is prepared by `MiAllocateVirtualMemoryPrepare`.

`MiAllocateVirtualMemory` calls into `MiReserveUserMemory`. This function checks if the `MEM_WRITE_WATCH` flag is set, and if so it calls `MiCreateWriteWatchView`.

`MiCreateWriteWatchView` sets the `WriteWatch` flag on the calling process (i.e. `EPROCESS->Flags.WriteWatch = 1`) and allocates a bitmap on the virtual address descriptor (VAD, i.e. `_MMVAD` struct), via `MiCreateVadEventBitmap`, that is used to track pages in the VAD that have been written to. The bitmap size is one bit per page, and the page size is fetched via `MiGetVadMandatoryPageSize`.

The bitmap is allocated using `MiAllocatePool`, using a tag value of "Mmww" (0x77776d4d). It is an `_RTL_BITMAP_EX` stored inside a `_MI_VAD_EVENT_BLOCK` struct, at `_MI_VAD_EVENT_BLOCK->BitMap`. It is attached to the VAD via `MiInsertVadEvent`.

The `_MI_VAD_EVENT_BLOCK` struct can be fetched for an `_MMVAD` struct using the `MiLocateLockedVadEvent` function. 

The userland `GetWriteWatch` function calls into `NtGetWriteWatch`, which effectively just loops through the VADs for a given range, checking if they've got `MEM_WRITE_WATCH` set, then finding the event blocks for those VADs and extracting the page indices/addresses that were written. The actual function is kinda long and complicated because this process involves TLB flushes, management of working sets, and pagetable lock, so I haven't included it in the RE'd code.

The userland `ResetWriteWatch` function calls into `NtResetWriteWatch`. This function finds the VAD associated with the address passed in, checks that the right flags are set, then flushes the dirty bits to the PFNs.

The core of the write watch behaviour is handled by `MiCaptureWriteWatchDirtyBit`. This function is called by a number of PTE management functions. The primary one is `MiWsleFlush`, which handles flushing working set pages. It is also called in some circumstances when the PTE validity bit is reverted, when addresses are marked as no access, when AWE region protection flags are changed, and during forking (surprise! Windows does actually have fork support).

