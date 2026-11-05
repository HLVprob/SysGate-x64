# SysGate-x64

Windows 11 x64 mimarisi için dinamik SSN çözümleyici ve indirect syscall kütüphanesi.

Bu proje, User-mode seviyesindeki API hook mekanizmalarını (EDR/AV detours) ve doğrudan syscall kullanımında ortaya çıkan RIP / call stack anomalilerini aşmak amacıyla geliştirilmiştir.

## Nasıl Çalışıyor?

1. **PEB Traversal:** `GetModuleHandle` veya `LoadLibrary` çağırmadan doğrudan Process Environment Block (`GS:[0x60]`) üzerinden `ntdll.dll` taban adresini bulur.
2. **Topolojik SSN Bulma (Address Sorting):** ntdll içindeki export tablosu taranarak `Zw*` fonksiyonları toplanır. Windows x64 mimarisinde syscall stub'ları hafızada SSN sırasına göre dizildiği için, fonksiyon adresleri küçükten büyüğe sıralandığında index doğrudan **SSN** değerini verir (Tartarus' Gate mantığı). Bu sayede fonksiyona hook (5-byte JMP) atılmış olsa bile SSN doğru çözülür.
3. **Indirect Syscall:** Kendi kodumuz içinde `syscall` çalıştırmak yerine, `ntdll.dll` adres uzayında bulunan `syscall; ret` (0x0F 0x05 0xC3) gadget'ına zıplanır. Böylece kernel stack izlemesinde (call trace) çağrının ntdll içinden geldiği görülür.
4. **x64 Calling Convention (MASM):** `sysgate_asm.asm` içerisinde kernel geçişi için ilk parametre `R10` yazmacına (`RCX` yerine) atanır, shadow space ve 16-byte stack hizalaması korunur.

## Dosya Yapısı

* `include/sysgate.h` - Struct tanımları ve prototipler.
* `src/sysgate.c` - PEB okuma, export tablosu ayrıştırma ve SSN sıralama algoritması.
* `src/sysgate_asm.asm` - MASM x64 dolaylı çağrı yöneticisi.
* `src/main.c` - NtAllocateVirtualMemory, NtProtectVirtualMemory ve NtFreeVirtualMemory ile test harness.
* `build.bat` - MSVC 2022 (cl.exe ve ml64.exe) derleme betiği.

## Derleme ve Çalıştırma

Visual Studio 2022 C++ araçları yüklüyse:

```cmd
build.bat
```

## Örnek Çıktı

```
[*] SysGate baslatiliyor (PEB parsing)...
[+] ntdll.dll adresi   : 0x00007FFA26AA0000
[+] 'syscall; ret' adr : 0x00007FFA26C018C2
[+] Toplam Zw fonksiyon: 490

[*] Dinamik SSN Cozumleri:
    -> NtAllocateVirtualMemory : SSN = 0x0018
    -> NtProtectVirtualMemory  : SSN = 0x0050
    -> NtFreeVirtualMemory     : SSN = 0x001E

[*] Indirect syscall ile bellek ayriliyor (NtAllocateVirtualMemory)...
[+] Bellek ayrildi: 0x000001D015AE0000 (Boyut: 0x1000)
[+] Bellek alanina test verisi yazildi.
[*] Bellek korumasi degistiriliyor (NtProtectVirtualMemory)...
[+] Bellek korumasi guncellendi (Eski koruma: 0x0004)
[*] Bellek serbest birakiliyor (NtFreeVirtualMemory)...
[+] Bellek basariyla serbest birakildi.

[✓] Tum dolayli syscall testleri basariyla gecti (STATUS_SUCCESS).
```

## Lisans
MIT
