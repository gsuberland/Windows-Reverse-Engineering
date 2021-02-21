/*
ntoskrnl.exe (ntkrnlmp.exe) - 10.0.19041.804 (WinBuild.160101.0800)
from Windows 10 Pro for Workstations (20H2 19042.804)
hash: d0051bfdd4c3622d135b754a9df8b4f7a458e3072be8ac94e798b649758593bb
reversed 2021-02-20
*/


/* MiCreateWriteWatchView creates a write watch view for a VAD. This is used with MEM_WRITE_WATCH on VirtualProtect.
   
   Sets up the VAD event bitmap and sets the WriteWatch flag on the process.
   
   Callers are MiReserveUserMemory (likely called as part of VirtualAlloc) and MiAllocateChildVads. */

NTSTATUS MiCreateWriteWatchView(_EPROCESS *Process,_MMVAD *Vad,size_t Size)
{
  NTSTATUS status;
  size_t vadPageSize;
  
  vadPageSize = MiGetVadMandatoryPageSize(Vad);
  status = MiCreateVadEventBitmap(Process,(_MMVAD *)Vad,((Size - 1) + vadPageSize & ~(vadPageSize - 1)) / vadPageSize,4);
  if (-1 < status) {
    LOCK();
          /* Process->Flags.WriteWatch = 1; */
    Process->FlagsUnion = Process->FlagsUnion | 0x8000;
    status = 0;
  }
  return status;
}



NTSTATUS MiCreateVadEventBitmap(_EPROCESS *Process,_MMVAD *Vad,size_t NumberOfPages,ulong WaitReason)
{
  NTSTATUS status;
  _MI_VAD_EVENT_BLOCK *vadEventBlock;
  SIZE_T bitmapSize;
  
  bitmapSize = ((ulonglong)((NumberOfPages & 0x3f) != 0) + 9 + (NumberOfPages >> 6)) * 8;
  vadEventBlock = (_MI_VAD_EVENT_BLOCK *)MiAllocatePool(0x40,bitmapSize,2004315469);
  if (vadEventBlock == (_MI_VAD_EVENT_BLOCK *)0x0) {
    status = 0xC000009A;
  }
  else {
    status = PsChargeProcessNonPagedPoolQuota(Process,bitmapSize);
    if (status < 0) {
      ExFreePool(vadEventBlock);
    }
    else {
      vadEventBlock->WaitReason = WaitReason;
          /* vadEventBlock->Bitmap.Buffer = ... */
      *(_MI_VAD_EVENT_BLOCK **)&(vadEventBlock->field_0x8).field_0x8 = vadEventBlock + 1;
          /* vadEventBlock->Bitmap.SizeOfBitMap */
      *(size_t *)&vadEventBlock->field_0x8 = NumberOfPages;
      MiInsertVadEvent(Vad,vadEventBlock,1);
      status = 0;
    }
  }
  return status;
}



/* This is fairly rough RE work; I'm not 100% sure on everything here. */
void MiInsertVadEvent(_MMVAD *Vad,_MI_VAD_EVENT_BLOCK *EventBlock,int UnknownFlag)
{
  KIRQL irql;
  _KLOCK_ENTRY_u_48 *p_Var1;
  _KLOCK_ENTRY_u_48 *SpinLock;
  longlong in_GS_OFFSET;
  _ETHREAD *thread;
  
  if (UnknownFlag == 1) {
    SpinLock = (_KLOCK_ENTRY_u_48 *)&DAT_140c4f600;
    thread = *(_ETHREAD **)(*(longlong *)(in_GS_OFFSET + 0x188) + 0xb8);
    p_Var1 = &thread->LockEntries[0].field_0x30;
    if ((*(byte *)&thread->LockEntries[2].field_0x20.field_0x8 & 7) != 2) {
      SpinLock = &thread->LockEntries[2].field_0x30;
    }
    irql = ExAcquireSpinLockExclusive((PKSPIN_LOCK)SpinLock);
    *(undefined4 *)&SpinLock->field_0x4 = 0;
  }
  else {
    irql = '\x11';
    p_Var1 = (_KLOCK_ENTRY_u_48 *)0x0;
  }
  EventBlock->Next = (Vad->Core).EventList;
  (Vad->Core).EventList = EventBlock;
  if (irql != '\x11') {
    MiUnlockWorkingSetExclusive(p_Var1);
  }
  return;
}



/* This function sets the page dirty bit in a VAD, for later use with GetWriteWatch.
   
   The write watch bitmap is created by MiCreateVadEventBitmap.
   
   This function is called by MiRevertValidPte, MiWsleFlush, MiMakeVaRangeNoAccess, MiMakeCombineCandidateClean, MiProtectAweRegion, and
   MiBuildForkPte. */

void MiCaptureWriteWatchDirtyBit(_EPROCESS *Process,ULONG_PTR Address,_MMVAD *Vad)
{
  byte *dirtyPageData;
  _MI_VAD_EVENT_BLOCK *lockedVadEvent;
  SIZE_T vadMandatoryPageSize;
  _MMVAD *vad;
  ULONG_PTR pageAddressOffsetInVad;
  _MMVAD_FLAGS vadFlags;
  
          /* Process->FlagsUnion is an incorrect union reference from Ghidra's decompiler. Actually references Process->Flags
             (_EPROCESS+0x464)
             Bit 5 (flags&0x20) appears to be VmDeleted.
             Interestingly there is a WriteWatch flag in bit 15 (flags&0x80) but that isn't referred to here. */
  if ((Process->FlagsUnion & 0x20) == 0) {
    if ((Vad == (_MMVAD *)0x0) && (Vad = MiLocateAddress((PVOID)Address), (_MMVAD *)Vad == (_MMVAD *)0x0)) {
      return;
    }
          /* 
             (Vad->Core).u is an incorrect union reference from Ghidra's decompiler. Actually references Vad->Core.LongFlags
             I initially thought this referenced VadFlags in the same union, but the bitfield accesses didn't line up.
             
             LongFlags is a combination of MEM_* constants and PAGE_* constants that you'd pass to VirtualAlloc.
             0x04 is PAGE_READWRITE, 0x300000 is MEM_WRITE_WATCH | MEM_TOP_DOWN
              */
    vadFlags = *(_MMVAD_FLAGS *)&(((_MMVAD *)Vad)->Core).u;
          /* if ((vadFlags & PAGE_READWRITE == 0) && (vadFlags & (MEM_WRITE_WATCH | MEM_TOP_DOWN) == 0)) { ...
             
             Unsure why MEM_TOP_DOWN must be set here. This seems consistent with other parts of kernel code that are related to write
             watching. */
    if ((((uint)vadFlags & 4) == 0) && (((uint)vadFlags & 0x300000) == 0x300000)) {
      vad = (_MMVAD *)Vad;
      lockedVadEvent = MiLocateLockedVadEvent(Vad,DelayExecution);
      vadMandatoryPageSize = MiGetVadMandatoryPageSize(vad);
          /* This appears to calculate the index of the page in the VAD for the given address.
             
             address>>0xc is equivalent to address/4096, which it then subtracts from the starting page address.
             starting page address is just StartingVpn | StartingVpnHigh<<32 */
      pageAddressOffsetInVad =
           (Address >> 0xc) - (ulonglong)CONCAT14((((_MMVAD *)Vad)->Core).StartingVpnHigh,(((_MMVAD *)Vad)->Core).StartingVpn);
      MiLockVadCore(Vad,pageAddressOffsetInVad % vadMandatoryPageSize);
          /* _MI_VAD_EVENT_BLOCK+0x8 is a union containing a whole bunch of stuff, so it's not possible to know for sure what's being
             touched here.
             
             However, intuition says that _MI_VAD_EVENT_BLOCK.BitMap (and _RTL_BITMAP_EX) would make sense if we're storing dirty page bits,
             and _RTL_BITMAP_EX+0x8 is the bitmap buffer.
             
             This implies that the original code looks like this:
             
             byte* dirtyPageData = (byte*)lockedVadEvent->Bitmap.Buffer;
             int bitmapOffsetByte = pageIndex / 8;
             int bitmapOffsetBit = 1 << (pageIndex & 3);
             *(dirtyPageData + bitmapOffsetByte) |= bitmapOffsetBit;
             
             This is setting the dirty bit on the current page in the VAD bitmap. */
      dirtyPageData = (byte *)(*(longlong *)&(lockedVadEvent->unlabelled8).field_0x8 +
                       ((longlong)(pageAddressOffsetInVad / vadMandatoryPageSize) >> 3));
      *dirtyPageData = *dirtyPageData | '\x01' << (pageAddressOffsetInVad / vadMandatoryPageSize & 7);
      MiUnlockVadCore(Vad,2);
    }
  }
  return;
}



_MI_VAD_EVENT_BLOCK * MiLocateLockedVadEvent(_MMVAD *Vad,_KWAIT_REASON waitReason)
{
  _MI_VAD_EVENT_BLOCK *vadEventBlock;
  
  vadEventBlock = (_MI_VAD_EVENT_BLOCK *)(Vad->Core).EventList;
  while ((vadEventBlock != (_MI_VAD_EVENT_BLOCK *)0x0 && ((vadEventBlock->WaitReason & waitReason) == 0))) {
    vadEventBlock = vadEventBlock->Next;
  }
  return vadEventBlock;
}



void MiLocateVadEvent(_MMVAD *Vad,_KWAIT_REASON WaitReason)
{
  MiLocateLockedVadEvent(Vad,WaitReason);
  return;
}



SIZE_T MiGetVadMandatoryPageSize(_MMVAD *Vad)
{
  uint vadFlags;
  
          /* Ghidra incorrectly picks up the union instead of the flags field here. */
  vadFlags = (Vad->Core).u;
  if ((*(ulonglong *)(&MiVadPageSizes + (ulonglong)(vadFlags >> 0x12 & 3) * 8) < 0x200) && ((vadFlags >> 0x16 & 1) == 0)) {
    return 1;
  }
  return *(ulonglong *)(&MiVadPageSizes + (ulonglong)(vadFlags >> 0x12 & 3) * 8);
}



uint MiLockVadCore(_MMVAD *Vad,ULONG_PTR PageAddress)
{
  longlong lVar1;
  uint vadFlags;
  longlong in_GS_OFFSET;
  byte in_CR8;
  uint *pVadFlags;
  
  if (((KiIrqlFlags != 0) && ((KiIrqlFlags & 1) != 0)) && (in_CR8 < 0x10)) {
          /* Unsure what GS:[0x20] is but that huge offset is weird. */
    lVar1 = *(longlong *)(*(longlong *)(in_GS_OFFSET + 0x20) + 0x84b8);
    *(uint *)(lVar1 + 0x14) = *(uint *)(lVar1 + 0x14) | (uint)(-1 << (in_CR8 + 1 & 0x3f)) & 4;
  }
  vadFlags = (Vad->Core).u;
  while( true ) {
    while ((vadFlags & 1) != 0) {
      if ((vadFlags & 2) == 0) {
        LOCK();
        pVadFlags = &(Vad->Core).u;
        if (vadFlags == *pVadFlags) {
          *pVadFlags = vadFlags | 2;
        }
        else {
          vadFlags = *pVadFlags;
        }
      }
      else {
        do {
          KeYieldProcessorEx();
          vadFlags = (Vad->Core).u;
        } while ((vadFlags & 1) != 0);
      }
    }
    LOCK();
    pVadFlags = &(Vad->Core).u;
    if (vadFlags == *pVadFlags) break;
    vadFlags = *pVadFlags;
  }
  *pVadFlags = vadFlags & 0xfffffffd | 1;
  return vadFlags & 0xffffff00 | (uint)in_CR8;
}



uint MiUnlockVadCore(_MMVAD *Vad,byte param_2)
{
  uint *puVar1;
  ulonglong uVar2;
  longlong lVar3;
  uint uVar4;
  uint uVar5;
  longlong in_GS_OFFSET;
  uint in_CR8;
  
  uVar4 = (Vad->Core).u;
  while( true ) {
    LOCK();
    puVar1 = &(Vad->Core).u;
    if (uVar4 == *puVar1) break;
    uVar4 = *puVar1;
  }
  *puVar1 = uVar4 & 0xfffffffc;
  uVar4 = KiIrqlFlags;
  if ((((KiIrqlFlags != 0) && ((KiIrqlFlags & 1) != 0)) && (uVar4 = in_CR8, (byte)in_CR8 < 0x10)) &&
     ((param_2 < 0x10 && (1 < (byte)in_CR8)))) {
          /* Again with this weird GS:[0x20]+0x84b8 offset. */
    uVar2 = *(ulonglong *)(in_GS_OFFSET + 0x20);
    lVar3 = *(longlong *)(uVar2 + 0x84b8);
    uVar4 = ~((uint)(-1 << (param_2 + 1 & 0x3f)) & 0xffff);
    uVar5 = *(uint *)(lVar3 + 0x14) & uVar4;
    *(uint *)(lVar3 + 0x14) = uVar5;
    if (uVar5 == 0) {
      uVar4 = KiRemoveSystemWorkPriorityKick(uVar2);
    }
  }
  return uVar4;
}


