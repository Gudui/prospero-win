# Wired Xbox 360 input

The title and Wine exchange four independent XInput users through pw_wine_sink.
The old pw_wine_set_pad/pw_wine_pad/rumble API remains user 0. The indexed API
adds per-user subtype, vendor/product/revision and capability flags, with packet
numbers that change only on state/identity changes and reconnection. New Wine
patch 0470 uses indexed exports when available and falls back to user 0 on an
older ntdll. Its PE/Unix modules must be built and deployed together.

The portable src/pw_xinput_usb parser accepts exactly the 20-byte wired-360
00/14 input transfer. Button bits, triggers and signed axes pass through unchanged.
It validates cached device/interface/endpoint descriptors: alt 0, FF/5D/01,
interrupt IN, 20..64-byte maximum packet. Known 1430:4748 X-plorer identity uses
XInput subtype Guitar (7); unlisted compatible wired-360 devices retain gamepad
subtype (1). Identity never depends on a fixed USB bus/address.

native/pw_xinput_usb_freebsd owns /dev/usb enumeration, cached descriptor ioctls,
O_RDONLY|O_NONBLOCK endpoint opens, short-transfer setup and bounded reads.
It has no reset, configuration request, driver detach, output report or USB FS
claim. Descriptor ioctl numbers and FIFO short-transfer setup follow FreeBSD 9
sys/dev/usb/usb_ioctl.h (105/107/108/113). The PS5 ABI and read path require their
own target qualification; FreeBSD source alone is not proof of firmware behavior.

The title bridge reserves user 0 for the DualSense and uses users 1..3 for USB
controllers. It scans every five seconds, drains at most eight transfers per user
per poll, connects a user only after a valid report and clears it on disconnect.
No new worker thread is started. Guitar output/rumble is not implemented and the
USB users advertise no force-feedback capability. Without the indexed runtime
exports, normal USB injection remains disabled.

PW_USB360_CAPTURE=1 builds a diagnostic raw-input capture: up to 256 changed
reports per device are logged as hexadecimal, with no USB XInput injection.
This mode can qualify interrupt input against the existing Wine runtime before
rebuilding its PE/Unix XInput modules. It is not a gameplay qualification.

Host checks: test_pw_xinput_usb, test_pw_xinput_usb_freebsd, test_pw_xinput_usb_wine,
test_pw_wine_sink and test_xinput_title_slots.py. The latter executes the patch's
actual Unix dispatch and PE state/capability/rumble helpers against the real sink.
They establish host logic only. Target report interpretation, physical fret/strum/
whammy mapping, hotplug, independent controller enumeration and gameplay remain
separate acceptance boundaries.
