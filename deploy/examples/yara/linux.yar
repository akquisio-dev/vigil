// Starter rules for Linux servers. Copy to the server's yara_dir and add
// your own. vigil scans suspicious and new programs, programs in evidence
// snapshots and new programs in temp directories with them.

rule Linux_Miner_XMRig_Family : miner
{
  meta:
    description = "XMRig or a fork of it (crypto miner)"
  strings:
    $a = "xmrig" nocase
    $b = "stratum+tcp://"
    $c = "donate-level"
    $d = "randomx" nocase
    $e = "cryptonight" nocase
    $f = "nicehash" nocase
  condition:
    uint32(0) == 0x464c457f and 3 of them
}

rule Linux_Miner_Script : miner
{
  meta:
    description = "Script that downloads or starts a crypto miner"
  strings:
    $pool1 = "stratum+tcp://"
    $pool2 = "stratum+ssl://"
    $x1 = "xmrig" nocase
    $x2 = "--donate-level"
    $kill1 = "pkill -f" nocase
    $kill2 = "kdevtmpfsi"
    $kill3 = "kinsing"
  condition:
    uint32(0) != 0x464c457f and filesize < 1MB and (1 of ($pool*)) and (1 of ($x*) or 2 of ($kill*))
}

rule Linux_Botnet_Mirai_Family : botnet
{
  meta:
    description = "Mirai or a variant (IoT/DDoS botnet)"
  strings:
    $a = "/bin/busybox" nocase
    $b = "/dev/watchdog"
    $c = "/dev/misc/watchdog"
    $d = "TSource Engine Query"
    $e = "LZRD"
    $f = "dvrHelper"
    $g = "MIRAI"
    $h = "attack_udp" nocase
  condition:
    uint32(0) == 0x464c457f and filesize < 3MB and 4 of them
}

rule Linux_Botnet_IRC_Kaiten : botnet
{
  meta:
    description = "Kaiten/Tsunami style IRC bot"
  strings:
    $a = "NOTICE %s :" nocase
    $b = "PRIVMSG %s :" nocase
    $c = "KILLALL"
    $d = "GETSPOOFS"
    $e = "PAN <target>" nocase
    $f = "TSUNAMI" nocase
    $g = "UNKNOWNSERVER" nocase
  condition:
    uint32(0) == 0x464c457f and 4 of them
}

rule Linux_Kinsing : miner
{
  meta:
    description = "Kinsing malware (miner dropper that kills other miners)"
  strings:
    $a = "kinsing" nocase
    $b = "kdevtmpfsi"
    $c = "masscan" nocase
    $d = "/tmp/kdevtmpfsi"
    $e = "redis" nocase
  condition:
    uint32(0) == 0x464c457f and 3 of them
}

rule Linux_Reverse_Shell_Script : shell
{
  meta:
    description = "Script that connects a shell to a remote address"
  strings:
    $dev = /(sh|bash)( -i)?[^\n]{0,20}\/dev\/(tcp|udp)\/[^\s\/]+\/[0-9]{2,5}/
    $nc = /\bnc(at)? [^\n]{0,60}-e +\/bin\/(ba)?sh/
    $pty = /pty\.spawn\(["'](\/bin\/)?(ba)?sh/
    $sock = "socket.socket("
    $dup = /os\.dup2\([^)]*fileno\(\)[^)]*,\s*0\)/
  condition:
    uint32(0) != 0x464c457f and filesize < 200KB and ($dev or $nc or $pty or ($sock and $dup))
}

rule Linux_ELF_UPX_Packed : packer
{
  meta:
    description = "UPX-packed ELF program (rare on servers, common for malware)"
  strings:
    $upx1 = "UPX!"
    $upx2 = "$Info: This file is packed with the UPX"
  condition:
    uint32(0) == 0x464c457f and any of them
}
