# Tenda AC5v3 goform/setWifi wifiPwd Parameter Stack-Based Buffer Overflow
- Affected Product: `Tenda AC5 v3 (firmware V02.03.01.111_multi)`
- Vulnerability Class: `CWE-121` (`Stack-based Buffer Overflow`) / `CWE-787` (`Out-of-bounds Write`)
- Component: `/goform/setWifi` endpoint, `wifiPwd` POST parameter
- CVSS 3.1 Score: `7.2 (High)` — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
- `Privileges Required`: Authenticated (admin session) — the request requires a valid session `cookie` containing the `admin` credentials, so this is a `post-authentication vulnerability`, not pre-auth remote.

**Description**
The `setWifi` handler in the AC5v3 web management interface `fails to validate the length` of the `wifiPwd` parameter before copying it into a fixed-size stack buffer. An authenticated attacker (or an attacker who has otherwise obtained a valid admin session, credential theft, or a separate auth bypass) can submit an oversized wifiPwd value to corrupt stack memory and gain control of the program counter.

**Proof Of Concept**
1. POST /goform/setWifi HTTP/1.1 to 192.168.0.1, sent via Burp Suite Repeater, with a valid authenticated session cookie
2. wifiPwd= followed by ~500+ bytes of 0x41 (A) padding, alongside the other required setWifi form fields
3. HTTP layer returns 200 OK, {"errCode":"0"} — no input validation rejection
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/blog/ac5/payload.png)
4. PC register overwritten to 41414141, matching the injected padding exactly — confirming direct instruction-pointer control, not just a DoS crash.
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/blog/ac5/PC.png)

5. stack dump is saturated with the 41414141 pattern across dozens of registers/stack slots.
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/blog/ac5/1.png)
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/blog/ac5/2.png)

**Persistent NVRAM Corruption**

Memory analysis at address `0x80001400` shows the injected `wifiPwd` value overwrites the NVRAM key `wl0_wpa_psk` (the WPA pre-shared key for the primary wireless interface). Immediately preceding this field, intact NVRAM entries are visible (`wl0.1_akm=`, `_WLAN1_11N_THER=28`, `tc_10=`, `dmz_ipaddr_en=0`), confirming this is live configuration memory, not stack. The `0x41` padding runs unbroken for over 320 bytes starting at `0x80001444` through at least `0x80001584`, well beyond the intended boundary of the `wl0_wpa_psk` field.
![](https://yzdhzjjwtsjwhabhuksf.supabase.co/storage/v1/object/public/assets/blog/ac5/pwd.png) 

This corruption persists across reboots as the device re-parses the malformed NVRAM block on every boot. This elevates the vulnerability from a transient denial-of-service to a **persistent** one; recovery likely requires a factory reset or manual NVRAM wipe. It also raises the possibility that a precisely crafted payload could target adjacent NVRAM fields for corruption beyond a simple crash.

**Impact**
This vulnerability allows an authenticated attacker to overwrite the program counter on the device's MIPS processor, which is very likely exploitable for remote code execution given demonstrated instruction-pointer control. Independently, the confirmed NVRAM corruption causes persistent denial-of-service — the device fails to boot cleanly and re-crashes on every restart, likely requiring a factory reset to recover. This dual impact (potential RCE + persistent DoS surviving reboot) distinguishes this finding from typical transient stack-overflow crashes in this device family.

**Suggested Remediation**
Vendor should implement server-side length validation on the `wifiPwd` parameter in the `setWifi` handler prior to copying it into any fixed-size buffer, and apply equivalent bounds-checking to the corresponding NVRAM write path for `wl0_wpa_psk`.
