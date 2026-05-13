def ror13_with_len(s):
    h = len(s)
    for c in s:
        h = ((h >> 13) | (h << (32 - 13))) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return hex(h)

def ror13_unicode_lower_with_len(s):
    s = s.lower()
    h = len(s)
    for c in s:
        h = ((h >> 13) | (h << (32 - 13))) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return hex(h)

print(f"GetProcAddress: {ror13_with_len('GetProcAddress')}")
print(f"NtAllocateVirtualMemory: {ror13_with_len('NtAllocateVirtualMemory')}")
print(f"NtWriteVirtualMemory: {ror13_with_len('NtWriteVirtualMemory')}")
print(f"NtQueueApcThread: {ror13_with_len('NtQueueApcThread')}")
print(f"ntdll.dll: {ror13_unicode_lower_with_len('ntdll.dll')}")
print(f"kernel32.dll: {ror13_unicode_lower_with_len('kernel32.dll')}")
