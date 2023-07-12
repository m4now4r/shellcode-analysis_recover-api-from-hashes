# shellcode-analysis_recover-api-from-hashes

The shellcode is mentioned by herrcore in his research [AMSI Bypass In The Wild](https://research.openanalysis.net/asyncrat/amsi/anti-detection/2023/05/28/amsifun.html)

Here is the pseudocode of **mw_get_api_from_hash** function:

  ```C    
    __int64 *__fastcall mw_get_api_from_hash(sc_ctx *arg_sc_ctx, PE_BASE64 arg_dll_base_addr, __int64 arg_pre_api_hash, __int64 arg_seed_value)
    {
          
      v_e_lfanew = arg_dll_base_addr.dosHeaders->e_lfanew;
      // get export directory RVA
      v_export_dir_rva = *(&arg_dll_base_addr.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + v_e_lfanew);
      if ( !v_export_dir_rva )
        return 0i64;
      vp_export_dir = (arg_dll_base_addr.baseAddress + v_export_dir_rva);
      // check current dll has exported functions?
      LODWORD(v_numExportNames) = *(arg_dll_base_addr.baseAddress + v_export_dir_rva + offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfNames));
      if ( !v_numExportNames )
        return 0i64;
      v_idx = 0i64;
      vp_funcAddrTbl = arg_dll_base_addr.baseAddress + vp_export_dir->AddressOfFunctions;
      vp_strDllName = arg_dll_base_addr.baseAddress + vp_export_dir->Name;
      vp_namesAddrTbl = arg_dll_base_addr.baseAddress + vp_export_dir->AddressOfNames;
      vp_namesOrdTbl = arg_dll_base_addr.baseAddress + vp_export_dir->AddressOfNameOrdinals;
      // convert dll name to lowerase chars
      v_dllNameByteVal = *vp_strDllName;
      if ( *vp_strDllName )
      {
        i = 0i64;
        do
        {
          v_idx = (v_idx + 1);
          vp_strDllNameInLowerCase[i] = v_dllNameByteVal | 0x20;// convert to lower case
          i = v_idx;
          v_dllNameByteVal = vp_strDllName[v_idx];
        }
        while ( v_dllNameByteVal );
      }
      vp_strDllNameInLowerCase[v_idx] = 0;
    
      // calc dll hash based on seed value
      v_dllNameHash = mw_calc_hash(vp_strDllNameInLowerCase, arg_seed_value);
      while ( TRUE )
      {
        v_numExportNames = (v_numExportNames - 1);
    
        // calc api hash and compare with pre-hash
        if ( (v_dllNameHash ^ mw_calc_hash(arg_dll_base_addr.baseAddress + vp_namesAddrTbl[v_numExportNames], arg_seed_value)) == arg_pre_api_hash )
          break;
        if ( !v_numExportNames )
          return 0i64;
      }
      v_apiAddr = arg_dll_base_addr.baseAddress + vp_funcAddrTbl[vp_namesOrdTbl[v_numExportNames]];
      if ( v_apiAddr < vp_export_dir || v_apiAddr >= vp_export_dir + *(arg_dll_base_addr.baseAddress + v_e_lfanew + 0x8C) )
        return v_apiAddr;
      LODWORD(v17) = 0;
      if ( *v_apiAddr )
      {
        do
        {
          if ( v17 >= 0x3C )
            break;
          LibFileName[v17] = *(v17 + v_apiAddr);
          if ( *(v17 + v_apiAddr) == 0x2E )
            break;
          v17 = (v17 + 1);
        }
        while ( *(v17 + v_apiAddr) );
      }
      LibFileName[(v17 + 1)] = 'd';
      LibFileName[(v17 + 2)] = 'l';
      LibFileName[(v17 + 3)] = 'l';
      v18 = (v17 + 4);
      v19 = ((v17 + 1) + v_apiAddr);
      LibFileName[v18] = 0;
      LODWORD(v20) = 0;
      if ( *v19 )
      {
        do
        {
          if ( v20 >= 0x7F )
            break;
          v21 = v20;
          v20 = (v20 + 1);
          v_strApiName[v21] = v19[v21];
        }
        while ( v19[v20] );
      }
      v_strApiName[v20] = 0;
      v_dll_handle = arg_sc_ctx->vp_sc_apis.LoadLibraryA(LibFileName);
      if ( v_dll_handle )
        v_apiAddr = arg_sc_ctx->vp_sc_apis.GetProcAddress(v_dll_handle, v_strApiName);
      else
        v_apiAddr = 0i64;
      return v_apiAddr;
    }

```

 - First, it will calculate Dll's hash (the Dll name is converted to lower case).
 - Second, it calculate API's hash, xor with Dll's hash, and finally compare with the pre-calculated hash.

Here is the pseudocode of **mw_calc_hash** function:

   ```C
    __int64 __fastcall mw_calc_hash(const char *arg_strInput, __int64 arg_seed_value)
    {
      // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]
    
      v_strLen = 0i64;
      i = 0i64;
      j = 0;
      do
      {
        v_inputByteVal = arg_strInput[i];
        if ( !v_inputByteVal || i == 64 )
        {
          mw_memset(&v_strInputCopy[v_strLen], 0, 0x10 - v_strLen);
          v_strInputCopy[v_strLen] = 0x80;
          // check string length > 12
          if ( v_strLen >= 0xC )
          {
            arg_seed_value ^= mw_ror_rol_func(v_strInputCopy, arg_seed_value);
            mw_memset(v_strInputCopy, 0, 0x10u);
          }
          ++j;
          *&v_strInputCopy[0xC] = 8 * i;
        }
        else
        {
          // copy 16 bytes of input string to new location
          v_strInputCopy[v_strLen] = v_inputByteVal;
          i = (i + 1);
          v_strLen = (v_strLen + 1);
          if ( v_strLen != 16 )
            continue;
        }
        arg_seed_value ^= mw_ror_rol_func(v_strInputCopy, arg_seed_value);
        v_strLen = 0i64;
      }
      while ( !j );
      return arg_seed_value;
    }
```

And the  the pseudocode of **mw_ror_rol_func** function:

   ```C
    __int64 __fastcall mw_ror_rol_func(const char *arg_strInput, __int64 arg_seed_value)
    {
          
      v_strInput = *arg_strInput;
      v_seed_low_dw = arg_seed_value;
      v_seed_hi_dw = HIDWORD(arg_seed_value);       // v_tmp1 = arg_seed_value >> 32
      v_counter = 0;
      v_tmp1 = HIDWORD(v_strInput);
      v_tmp2 = DWORD2(v_strInput);
      v_tmp3 = DWORD1(v_strInput);
      v_tmp4 = v_strInput;
      do
      {
        v10 = v_tmp1;
        v_seed_low_dw = v_tmp4 ^ (v_seed_hi_dw + __ROR4__(v_seed_low_dw, 8));
        v_tmp1 = v_counter ^ (v_tmp4 + __ROR4__(v_tmp3, 8));
        v_tmp4 = v_tmp1 ^ __ROL4__(v_tmp4, 3);
        v_seed_hi_dw = v_seed_low_dw ^ __ROL4__(v_seed_hi_dw, 3);
        ++v_counter;
        v_tmp3 = v_tmp2;
        v_tmp2 = v10;
      }
      while ( v_counter < 0x1B );
      return __PAIR64__(v_seed_hi_dw, v_seed_low_dw);
    }
```

Based on all the functions above, I recreated the following Python code to find the API functions:

```Python
    import struct
    import pefile, os
    
    ROTATE_BITMASK = {
        8  : 0xff,
        16 : 0xffff,
        32 : 0xffffffff,
        64 : 0xffffffffffffffff,
    }
    
    most_common_dlls =  [
        'kernel32.dll', 'comctl32.dll', 'advapi32.dll', 'comdlg32.dll',
        'gdi32.dll', 'msvcrt.dll', 'netapi32.dll', 'ntdll.dll',
        'ntoskrnl.exe', 'oleaut32.dll', 'psapi.dll', 'shell32.dll',
        'shlwapi.dll', 'srsvc.dll', 'urlmon.dll', 'user32.dll',
        'winhttp.dll', 'wininet.dll', 'ws2_32.dll', 'wship6.dll',
        'advpack.dll', 'ole32.dll', 'rstrtmgr.dll', 'iphlpapi.dll',
        'activeds.dll', 'gdiplus.dll', 'gpedit.dll', 'mpr.dll',
        'bcrypt.dll', 'crypt32.dll', 'wtsapi32.dll', 'win32u.dll',
        'cryptbase.dll', 'combase.dll', 'winspool.drv', 'dnsapi.dll', 'mscoree.dll'
    ]
    
    win_path = "C:\\Windows"
    system32_path = os.path.join(win_path, "SysWOW64")
    
    API_HASHES_LIST = [
        0x5ABC026841136F5D, 0xA9237452A21EFD71, 0xE490D7B166D3755A, 0x57C11E5BCC7B9CB4, 0xBF2412ABF45446DF, 
        0xADF96E6C0505EA8A, 0x594FEA039A79B60D, 0xECC164DAA0FCEA0F, 0x150D322C3D76ED36, 0x0DD1F2BE5C56E4C4, 
        0x45A43F01049B0362, 0x86E888DDF17E90CE, 0x4C5141BF2CDD91D8, 0xD17086955AA0170E, 0xFC63214B890BCD9C, 
        0x6656FAA0CBA07327, 0xC23C2C3A6EE193AA, 0xA1F2982D4FDB2499, 0x762AA2255227A5A9, 0xED86A5C9D3B39361, 
        0xF86E660EBDBCF3F1, 0x642C02232067A013, 0xF7C6FC60DF7D6FC1, 0x0FE609D9B6567CBA, 0xCCE9678A6A7E0EA8, 
        0x5BD0DE8D8947E35F, 0xC23A6D682F626A38, 0x71F6DF36065E1E5F, 0x29ABE50E4C7999EB, 0x38DF23869D733C36, 
        0x7E0BC9AC72AFEADB, 0x72E0FADADC7AFC5D, 0xD3ABA35BF232EF12, 0x15E14562AD265B14, 0x1AE24AB831039324, 
        0x335A09A5A1641465, 0x4F317AD6F54B23B7, 0xA60687D566C7A017, 0xA791983775F52C3A, 0x46C54A2AB01FC648, 
        0x7557E4AD459C65B9, 0x29DE00A8CECD5F1C, 0x463AC62904A9B1F2, 0x3ADE90FDD6CC5E37, 0x4D0536F171C269DD, 
        0x91CA0B9BBE79F3F4, 0xD18FF002C0E76393, 0xE903E9C45EB27B8F, 0x10B4EB2917F4A07A, 0xC7210792A8937014, 
        0xC11F3E4BE37B7780, 0x6C3E8DFBC02FF28E
    ]
    
    def get_functions(dll_path):
        pe = pefile.PE(dll_path)
        if ((not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT')) or (pe.DIRECTORY_ENTRY_EXPORT is None)):
            print ("[*] No exports for %s" % dll_path)
            return []
        else:
            expname = []
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    expname.append(exp.name)
            return expname
    
    # This function is referenced at the following link: https://github.com/mandiant/flare-ida/blob/master/shellcode_hashes/make_sc_hash_db.py
    def ror(inVal, numShifts, dataSize=32):
        '''rotate right instruction emulation'''
        if numShifts == 0:
            return inVal
        if (numShifts < 0) or (numShifts > dataSize):
            raise ValueError('Bad numShifts')
        if (dataSize != 8) and (dataSize != 16) and (dataSize != 32) and (dataSize != 64):
            raise ValueError('Bad dataSize')
        bitMask = ROTATE_BITMASK[dataSize]
        return bitMask & ((inVal >> numShifts) | (inVal << (dataSize-numShifts)))
    
    # This function is referenced at the following link: https://github.com/mandiant/flare-ida/blob/master/shellcode_hashes/make_sc_hash_db.py
    def rol(inVal, numShifts, dataSize=32):
        '''rotate left instruction emulation'''
        if numShifts == 0:
            return inVal
        if (numShifts < 0) or (numShifts > dataSize):
            raise ValueError('Bad numShifts')
        if (dataSize != 8) and (dataSize != 16) and (dataSize != 32) and (dataSize != 64):
            raise ValueError('Bad dataSize')
        bitMask = ROTATE_BITMASK[dataSize]
        currVal = inVal
        return bitMask & ((inVal << numShifts) | (inVal >> (dataSize-numShifts)))
    
    def calc_hash(str_input):
        calced_hash = 0x0FF45B9236F36849
        v_strInputCopy = bytearray(16)
        v_strLen = 0
        i = 0
        j = 0
        while i < len(str_input):
            if i == 64 or str_input[i] == '\x00':
                for x in range(v_strLen, 16):
                    v_strInputCopy[x] = 0x0
                v_strInputCopy[v_strLen] = 0x80
                
                if v_strLen >= 0xC:
                    calced_hash ^= ror_rol_hash(bytes(v_strInputCopy),calced_hash)
                    v_strInputCopy = bytearray(16)
                
                j+=1
                v_strInputCopy[0xC:0x10] = (i*8).to_bytes(4, 'little')
            else:            
                v_inputByteVal = str_input[i]
                v_strInputCopy[v_strLen] = ord(v_inputByteVal)
                i += 1
                v_strLen += 1
                if v_strLen != 16:
                    continue
            calced_hash ^= ror_rol_hash(bytes(v_strInputCopy), calced_hash)
            v_strLen = 0
            if j:
                break
        
        return calced_hash
    
    def ror_rol_hash(data, seed):   
        v_seed_low_dw = seed & 0xFFFFFFFF
        v_seed_hi_dw = seed >> 32
        #print(hex(v_seed_hi_dw))
        v_tmp1 = struct.unpack('<I', data[0xC:0xC+4])[0]
        #print(hex(v_tmp1))
        v_tmp2 = struct.unpack('<I', data[0x8:0x8+4])[0]
        #print(hex(v_tmp2))
        v_tmp3 = struct.unpack('<I', data[0x4:0x4+4])[0]
        #print(hex(v_tmp3))
        v_tmp4 = struct.unpack('<I', data[0x0:0x0+4])[0]
        #print(hex(v_tmp4))
        
        v_counter = 0
        while (v_counter < 0x1B):
            v10 = v_tmp1
            v_seed_low_dw = (v_tmp4 ^ (v_seed_hi_dw + ror(v_seed_low_dw, 0x8))) & 0xFFFFFFFF # 000000004936F368
            v_tmp1 = (v_counter ^ (v_tmp4 + ror(v_tmp3, 0x8))) & 0xFFFFFFFF
            v_tmp4 = (v_tmp1 ^ rol(v_tmp4, 0x3)) & 0xFFFFFFFF
            v_seed_hi_dw = (v_seed_low_dw ^ rol(v_seed_hi_dw, 0x3)) & 0xFFFFFFFF
            v_tmp3 = v_tmp2
            v_tmp2 = v10
            v_counter += 1
        
        calced_seed = (v_seed_hi_dw << 32) + v_seed_low_dw
        #final_seed = calced_seed ^ SEED
        return calced_seed
    
    dll_hash = 0x0
    api_hash = 0x0
    for dll in most_common_dlls:
        dll_hash = calc_hash(dll + '\x00')
        dll_path = os.path.join(system32_path, dll)
        if os.path.isfile(dll_path):
            for f in get_functions(dll_path):
                api_hash = calc_hash(f.decode('utf-8') + '\x00')
                api_hash ^= dll_hash
                if api_hash in API_HASHES_LIST:
                    print ("API hash: 0x%02X --> API found: %s" % (api_hash,f))
```
Here is the result:
```C
    API hash: 0xC11F3E4BE37B7780 --> API found: b'AddVectoredExceptionHandler'
    API hash: 0x86E888DDF17E90CE --> API found: b'CreateThread'
    API hash: 0xFC63214B890BCD9C --> API found: b'GetCommandLineA'
    API hash: 0x6656FAA0CBA07327 --> API found: b'GetCommandLineW'
    API hash: 0xD17086955AA0170E --> API found: b'GetCurrentThread'
    API hash: 0xE490D7B166D3755A --> API found: b'GetModuleHandleA'
    API hash: 0xA9237452A21EFD71 --> API found: b'GetProcAddress'
    API hash: 0x4C5141BF2CDD91D8 --> API found: b'GetThreadContext'
    API hash: 0xDD1F2BE5C56E4C4 --> API found: b'GetUserDefaultLCID'
    API hash: 0x5ABC026841136F5D --> API found: b'LoadLibraryA'
    API hash: 0x150D322C3D76ED36 --> API found: b'MultiByteToWideChar'
    API hash: 0x6C3E8DFBC02FF28E --> API found: b'RemoveVectoredExceptionHandler'
    API hash: 0xECC164DAA0FCEA0F --> API found: b'Sleep'
    API hash: 0x57C11E5BCC7B9CB4 --> API found: b'VirtualAlloc'
    API hash: 0xBF2412ABF45446DF --> API found: b'VirtualFree'
    API hash: 0x594FEA039A79B60D --> API found: b'VirtualProtect'
    API hash: 0xADF96E6C0505EA8A --> API found: b'VirtualQuery'
    API hash: 0x45A43F01049B0362 --> API found: b'WaitForSingleObject'
    API hash: 0xC7210792A8937014 --> API found: b'NtContinue'
    API hash: 0xD18FF002C0E76393 --> API found: b'RtlCreateUnicodeString'
    API hash: 0x10B4EB2917F4A07A --> API found: b'RtlDecompressBuffer'
    API hash: 0x29DE00A8CECD5F1C --> API found: b'RtlEqualString'
    API hash: 0x7557E4AD459C65B9 --> API found: b'RtlEqualUnicodeString'
    API hash: 0x91CA0B9BBE79F3F4 --> API found: b'RtlExitUserProcess'
    API hash: 0x4D0536F171C269DD --> API found: b'RtlExitUserThread'
    API hash: 0xE903E9C45EB27B8F --> API found: b'RtlGetCompressionWorkSpaceSize'
    API hash: 0x3ADE90FDD6CC5E37 --> API found: b'RtlInitUnicodeString'
    API hash: 0x463AC62904A9B1F2 --> API found: b'RtlUnicodeStringToAnsiString'
    API hash: 0x5BD0DE8D8947E35F --> API found: b'LoadTypeLib'
    API hash: 0xA1F2982D4FDB2499 --> API found: b'SafeArrayCreate'
    API hash: 0x762AA2255227A5A9 --> API found: b'SafeArrayCreateVector'
    API hash: 0xF86E660EBDBCF3F1 --> API found: b'SafeArrayDestroy'
    API hash: 0x642C02232067A013 --> API found: b'SafeArrayGetLBound'
    API hash: 0xF7C6FC60DF7D6FC1 --> API found: b'SafeArrayGetUBound'
    API hash: 0xED86A5C9D3B39361 --> API found: b'SafeArrayPutElement'
    API hash: 0xFE609D9B6567CBA --> API found: b'SysAllocString'
    API hash: 0xCCE9678A6A7E0EA8 --> API found: b'SysFreeString'
    API hash: 0xC23C2C3A6EE193AA --> API found: b'CommandLineToArgvW'
    API hash: 0xD3ABA35BF232EF12 --> API found: b'HttpOpenRequestA'
    API hash: 0x1AE24AB831039324 --> API found: b'HttpQueryInfoA'
    API hash: 0x15E14562AD265B14 --> API found: b'HttpSendRequestA'
    API hash: 0x72E0FADADC7AFC5D --> API found: b'InternetCloseHandle'
    API hash: 0x29ABE50E4C7999EB --> API found: b'InternetConnectA'
    API hash: 0xC23A6D682F626A38 --> API found: b'InternetCrackUrlA'
    API hash: 0x71F6DF36065E1E5F --> API found: b'InternetOpenA'
    API hash: 0x7E0BC9AC72AFEADB --> API found: b'InternetReadFile'
    API hash: 0x38DF23869D733C36 --> API found: b'InternetSetOptionA'
    API hash: 0xA791983775F52C3A --> API found: b'CoCreateInstance'
    API hash: 0xA60687D566C7A017 --> API found: b'CoInitializeEx'
    API hash: 0x46C54A2AB01FC648 --> API found: b'CoUninitialize'
    API hash: 0x4F317AD6F54B23B7 --> API found: b'CLRCreateInstance'
    API hash: 0x335A09A5A1641465 --> API found: b'CorBindToRuntime'
```
