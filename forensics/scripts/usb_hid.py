#!/usr/bin/env python3
"""
usb_hid.py — decode USB HID keystrokes/mouse from a pcap.

A recurring forensics challenge: a USB capture of someone typing (the flag) on a
keyboard, or drawing it with a mouse. This pulls `usb.capdata` via tshark and
maps HID usage IDs back to characters.

  python3 usb_hid.py capture.pcapng            # auto (keyboard)
  python3 usb_hid.py capture.pcapng --mouse    # dump mouse deltas (plot them)

Needs tshark on PATH.
"""
import subprocess, sys, argparse

# HID usage ID -> (unshifted, shifted)
KEY = {
 0x04:('a','A'),0x05:('b','B'),0x06:('c','C'),0x07:('d','D'),0x08:('e','E'),
 0x09:('f','F'),0x0a:('g','G'),0x0b:('h','H'),0x0c:('i','I'),0x0d:('j','J'),
 0x0e:('k','K'),0x0f:('l','L'),0x10:('m','M'),0x11:('n','N'),0x12:('o','O'),
 0x13:('p','P'),0x14:('q','Q'),0x15:('r','R'),0x16:('s','S'),0x17:('t','T'),
 0x18:('u','U'),0x19:('v','V'),0x1a:('w','W'),0x1b:('x','X'),0x1c:('y','Y'),
 0x1d:('z','Z'),0x1e:('1','!'),0x1f:('2','@'),0x20:('3','#'),0x21:('4','$'),
 0x22:('5','%'),0x23:('6','^'),0x24:('7','&'),0x25:('8','*'),0x26:('9','('),
 0x27:('0',')'),0x28:('\n','\n'),0x29:('[ESC]','[ESC]'),0x2a:('[BS]','[BS]'),
 0x2b:('\t','\t'),0x2c:(' ',' '),0x2d:('-','_'),0x2e:('=','+'),0x2f:('[','{'),
 0x30:(']','}'),0x31:('\\','|'),0x33:(';',':'),0x34:("'",'"'),0x35:('`','~'),
 0x36:(',','<'),0x37:('.','>'),0x38:('/','?'),
}

def get_capdata(pcap):
    out = subprocess.run(
        ["tshark","-r",pcap,"-Y","usb.capdata","-T","fields","-e","usb.capdata"],
        capture_output=True, text=True)
    lines = [l.strip() for l in out.stdout.splitlines() if l.strip()]
    if not lines:  # some captures expose it as usbhid.data
        out = subprocess.run(
            ["tshark","-r",pcap,"-T","fields","-e","usbhid.data"],
            capture_output=True, text=True)
        lines = [l.strip() for l in out.stdout.splitlines() if l.strip()]
    return lines

def decode_keyboard(lines):
    text = []
    for hexstr in lines:
        b = bytes.fromhex(hexstr.replace(":", ""))
        if len(b) < 3:  # sometimes reports are 8 bytes; keycode at index 2
            continue
        # standard boot keyboard report: [modifiers, reserved, k1, k2, ...]
        mod = b[0]
        shift = bool(mod & 0x22)   # left/right shift
        for kc in b[2:]:
            if kc == 0: continue
            if kc in KEY:
                text.append(KEY[kc][1 if shift else 0])
            else:
                text.append(f"[{kc:#04x}]")
    return "".join(text)

def dump_mouse(lines):
    print("frame  dx    dy   buttons   (feed these as x,y deltas to a plotter)")
    x = y = 0
    for i, hexstr in enumerate(lines):
        b = bytes.fromhex(hexstr.replace(":", ""))
        if len(b) < 3: continue
        btn = b[0]
        dx = b[1] - 256 if b[1] > 127 else b[1]
        dy = b[2] - 256 if b[2] > 127 else b[2]
        x += dx; y += dy
        print(f"{i:5d}  {dx:4d}  {dy:4d}   {btn:#04x}   pos=({x},{y})")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--mouse", action="store_true")
    a = ap.parse_args()
    lines = get_capdata(a.pcap)
    if not lines:
        sys.exit("No usb.capdata / usbhid.data found. Is this a USB capture?")
    print(f"[*] {len(lines)} HID reports found\n")
    if a.mouse:
        dump_mouse(lines)
    else:
        print("=== decoded keystrokes ===")
        print(decode_keyboard(lines))
        print("\n(Backspaces shown as [BS] — apply them mentally, or the flag is right there.)")

if __name__ == "__main__":
    main()
