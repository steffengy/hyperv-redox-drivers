# Redox Hyperv Drivers
This is a toy/POC implementation that allows redox to work on HyperV Gen 2.  
Supported features combine the fairly minimum (keyboard, mouse and network working).

This requires the kernel patches in this repo as well, since:  
a) hyperv requires MSRs read/write.  
b) we need to support a non-PLT time source, else time and sleeps are just "stuck"  
c) we need to make sure context switches / timeouts are triggered by some IRQs  

# Motivation
I had an unfinished toy hyperv implementation for an UEFI toy kernel  
and wanted to try out redox and now - pretty much did kinda both at same time.


# Not implemented e.g. HV_SCSI_GUID

- NIC
- IDE
- SCSI
- SHUTDOWN
- HEARTBEAT
- KVP
- DM (Dynamic memory)
- VSS (Backup/Restore)
- Synthetic Video
- Synthetic FC
- FCOPY (Guest filecopy)
- NetworkDirect
- PCIE

# Limitations
* This is pretty much only a single CPU implementation, not taking into account multi CPU (per cpu block state).
* Ping times seem ~2-200ms, no idea if thats redox in general or this driver.
