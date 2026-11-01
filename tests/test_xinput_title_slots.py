#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Execute the patch's Unix dispatch and XInput helpers against the actual sink."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "wine/patches/0470-xinput-ps5-title-controller.patch"


def added_file(text, name):
    section = text.split("+++ b/" + name + "\n", 1)[1].split("diff --git ", 1)[0]
    return "\n".join(line[1:] for line in section.splitlines()
                     if line.startswith("+") and not line.startswith("+++"))


def function(text, name):
    start = text.index(name)
    start = text.rfind("\n", 0, start) + 1
    end = text.index("\n}", start) + 2
    return text[start:end]


def main():
    patch = PATCH.read_text()
    header = added_file(patch, "dlls/xinput1_3/unixlib.h")
    structs = header[header.index("struct xinput_pad_state"):header.index("#endif")]
    unix = added_file(patch, "dlls/xinput1_3/unixlib.c")
    unix = unix[unix.index("static int (*title_pad)"):unix.index("const unixlib_entry_t")]
    main_added = added_file(patch, "dlls/xinput1_3/main.c")
    state = function(main_added, "static BOOL title_pad_state(")
    rumble = function(main_added, "static void title_pad_rumble(")
    # Take the actual added capabilities branch, including its own validation.
    marker = main_added.index("        struct xinput_caps_params params")
    start = main_added.rfind("    if (has_title_pad())", 0, marker)
    end = main_added.index("\n    }", marker) + 6
    caps = main_added[start:end]
    harness = r"""
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include "wine/ps5/pw_wine_sink.h"
typedef uint32_t UINT32, DWORD;
typedef uint16_t UINT16;
typedef int16_t INT16, SHORT;
typedef uint8_t BYTE;
typedef int BOOL, NTSTATUS;
#define TRUE 1
#define FALSE 0
#define XUSER_MAX_COUNT 4
#define XINPUT_DEVTYPE_GAMEPAD 1
#define XINPUT_CAPS_FFB_SUPPORTED 1
#define STATUS_SUCCESS 0
#define STATUS_NOT_SUPPORTED 1
#define STATUS_INVALID_PARAMETER 2
#define STATUS_DEVICE_NOT_CONNECTED 3
#define ERROR_BAD_ARGUMENTS 160
#define ERROR_DEVICE_NOT_CONNECTED 1167
#define ERROR_SUCCESS 0
#define RTLD_DEFAULT 0
static int lookup_mode;
static void *fake_dlsym(int unused,const char *name)
{
    (void)unused;
    if(lookup_mode==2)return NULL;
    if(!strcmp(name,"pw_wine_pad"))return (void *)pw_wine_pad;
    if(!strcmp(name,"pw_wine_set_rumble"))return (void *)pw_wine_set_rumble;
    if(lookup_mode==1)return NULL;
    if(!strcmp(name,"pw_wine_pad_slot"))return (void *)pw_wine_pad_slot;
    if(!strcmp(name,"pw_wine_pad_caps"))return (void *)pw_wine_pad_caps;
    if(!strcmp(name,"pw_wine_set_rumble_slot"))return (void *)pw_wine_set_rumble_slot;
    return NULL;
}
#define dlsym fake_dlsym
""" + structs + unix + r"""
typedef struct {UINT16 wButtons; BYTE bLeftTrigger,bRightTrigger; INT16 sThumbLX,sThumbLY,sThumbRX,sThumbRY;} XINPUT_GAMEPAD;
typedef struct {DWORD dwPacketNumber; XINPUT_GAMEPAD Gamepad;} XINPUT_STATE;
typedef struct {UINT16 wLeftMotorSpeed,wRightMotorSpeed;} XINPUT_VIBRATION;
typedef struct { struct { BYTE Type,SubType; UINT16 Flags; XINPUT_GAMEPAD Gamepad; XINPUT_VIBRATION Vibration; } Capabilities; UINT16 VendorId,ProductId,VersionNumber; } XINPUT_CAPABILITIES_EX;
static int title_pad_enabled=TRUE;
static XINPUT_VIBRATION title_pad_vibration[4];
/* The patch's Unix-library pointer has this name too; rename only the PE handle. */
#define title_pad 1
static NTSTATUS __wine_unix_call(int handle,int func,void *args)
{
    assert(handle==1);
    switch(func) {
    case unix_pad_state:return pad_state(args);
    case unix_pad_rumble:return pad_rumble(args);
    case unix_pad_caps:return pad_caps(args);
    default:assert(0);return -1;
    }
}
static int has_title_pad(void) {return 1;}
""" + state + "\n" + rumble + r"""
static DWORD capabilities(DWORD index,XINPUT_CAPABILITIES_EX *caps)
{
""" + caps + r"""
    return 99;
}
#undef title_pad
int main(void)
{
    PwWinePad pad={0};
    PwWinePadCaps guitar={7,0x1430,0x4748,0x0100,0};
    XINPUT_STATE state;
    XINPUT_CAPABILITIES_EX caps;
    uint32_t left,right;
    _Static_assert(sizeof(struct xinput_pad_state)==sizeof(PwWinePad),"state ABI");
    _Static_assert(sizeof(struct xinput_pad_caps)==sizeof(PwWinePadCaps),"caps ABI");
    _Static_assert(offsetof(struct xinput_pad_caps,flags)==offsetof(PwWinePadCaps,flags),"caps offsets");
    assert(pad_init(NULL)==STATUS_SUCCESS);
    for(unsigned i=0;i<4;i++) {
        assert(!title_pad_state(i,&state));
        pad.buttons=(uint16_t)(0x1000+i); pad.thumb_rx=-32768;
        assert(!pw_wine_set_pad_slot(i,&pad,i?&guitar:NULL));
        assert(title_pad_state(i,&state) && state.Gamepad.wButtons==0x1000+i);
        assert(state.Gamepad.sThumbRX==-32768 && state.dwPacketNumber==1);
        assert(capabilities(i,&caps)==ERROR_SUCCESS);
        assert(caps.Capabilities.SubType==(i?7:1) && caps.VendorId==(i?0x1430:0x045e));
        assert(caps.ProductId==(i?0x4748:0x028e));
        assert(caps.Capabilities.Vibration.wLeftMotorSpeed==(i?0:255));
    }
    assert(!title_pad_state(4,&state) && capabilities(4,&caps)==ERROR_BAD_ARGUMENTS);
    assert(capabilities(1,NULL)==ERROR_BAD_ARGUMENTS);
    title_pad_enabled=FALSE;
    assert(title_pad_state(1,&state) && !state.Gamepad.wButtons && !state.Gamepad.sThumbRX);
    assert(capabilities(1,&caps)==ERROR_SUCCESS && caps.Capabilities.SubType==7);
    title_pad_enabled=TRUE;
    assert(title_pad_state(1,&state) && state.Gamepad.wButtons==0x1001);
    guitar.flags=PW_WINE_PAD_FFB;
    pw_wine_set_pad_slot(2,&pad,&guitar);
    title_pad_vibration[2]=(XINPUT_VIBRATION){123,456};
    title_pad_rumble(2);
    assert(pw_wine_rumble_slot(2,&left,&right) && left==123 && right==456);
    assert(!pw_wine_rumble_slot(0,&left,&right) && !left && !right);
    title_pad_enabled=FALSE; title_pad_rumble(2);
    assert(pw_wine_rumble_slot(2,&left,&right) && !left && !right);
    title_pad_enabled=TRUE; title_pad_rumble(2);
    assert(pw_wine_rumble_slot(2,&left,&right) && left==123 && right==456);
    pw_wine_set_pad_slot(2,NULL,NULL);
    assert(!title_pad_state(2,&state) && capabilities(2,&caps)==ERROR_DEVICE_NOT_CONNECTED);
    lookup_mode=1; assert(pad_init(NULL)==STATUS_SUCCESS); /* old ntdll */
    assert(title_pad_state(0,&state) && !title_pad_state(1,&state));
    assert(capabilities(0,&caps)==ERROR_SUCCESS && caps.VendorId==0x045e);
    assert(capabilities(1,&caps)==ERROR_DEVICE_NOT_CONNECTED);
    title_pad_vibration[0]=(XINPUT_VIBRATION){7,8}; title_pad_rumble(0);
    assert(pw_wine_rumble(&left,&right) && left==7 && right==8);
    lookup_mode=2; assert(pad_init(NULL)==STATUS_NOT_SUPPORTED); /* host HID fallback */
    return 0;
}
"""
    # pad_init's callback argument is unused in the real Unix ABI.
    with tempfile.TemporaryDirectory(prefix="pw-xinput-slots-") as directory:
        source=Path(directory)/"slots.c"
        executable=Path(directory)/"slots"
        source.write_text(harness)
        cc=shlex.split(os.environ.get("CC","cc"))
        subprocess.run(cc+["-O2","-std=c11","-Wall","-Wextra","-Werror","-Wno-unused-parameter",
                           "-I",str(ROOT),str(source),str(ROOT/"wine/ps5/pw_wine_sink.c"),
                           "-pthread","-o",str(executable)],check=True,timeout=60)
        subprocess.run([str(executable)],check=True,timeout=10)
    print("XInput patch: four slots, caps, enable/rumble, disconnect and old-ntdll fallback passed")


if __name__=="__main__":
    main()
