# Image-view file descriptor lifetime

Status: experimental. Patch 0870 is default off; patch 0880 proposes a
default-on selection alongside the shared mutex backend. Native/sanitizer
checks, complete SDK server builds and ordinary console application comparisons pass. Broader
section-lifetime and debugger behavior still needs real Wine coverage.

The 600-second fixed-route console capture records 68 image descriptor
releases, 22/22 replay steps and no recorded file-limit error. The regular
file descriptor census stays at 343 in the matched gameplay window, versus
402–405 in earlier diagnostic captures. Descriptor counts do not establish
exact kernel file-object occupancy. This run ends by the route runner's
ordinary `close-timeout`, not Wine-exit.

HL2 timedemo results reported by the console owner are 59.41 FPS with the
option off and 59.37 FPS with it on, both with Wine-exit. An immediate
same-console default-module control records 59.38 FPS with Wine-exit;
the lower absolute result than earlier ~59.8 runs affects all three arms.
The module comparison does not show a timing regression. These measurements
use the accepted NTDLL and the image-FD server candidate; they are not a
shared-mutex performance comparison or evidence of the 58/50 FPS goal.

Wine retains an FD object for each nonremovable image view. That object
also carries file sharing restrictions, its inode, names and the reserved
image address. Keeping this metadata is necessary after section handles
close, even when a completed private image mapping no longer needs the
native descriptor.

Patch 0870 releases that descriptor at image mapping-object destruction
only when all remaining FD object references are completed, unshared
`SEC_IMAGE` views. A census across current processes verifies their type,
shared backing and debugger state; the reference count must equal those
views plus the mapping owner being destroyed. Another live mapping or
temporary owner prevents release, so open section handles remain usable
for later views. The ordinary image-mapping path is unchanged.

Release additionally requires an inode-backed image mapping FD with no
user, delete disposition, pending inode close, inode or FD locks, async
queues, completion association or active poll dependency. The idle poll
registration is removed before close. Both native descriptor fields become
`-1`, preventing a later metadata destructor from closing a reused
descriptor number. Inode/sharing/name/address metadata remains alive until
the views release it. New sections skip descriptor-less objects when
searching for reusable mapping backing and instead duplicate their live
source file normally.

Data-file mappings, anonymous sections and writable shared image backing
are unchanged. Non-image entries, including any NLS data mappings, are not
implicitly eligible. Resource savings must be measured; inode groups and
descriptor counts do not prove the number of distinct open file objects.

Already attached debuggers prevent release. If a debugger attaches after
release, its image event has no file handle for that metadata-only view.
The image name and information remain available. The patch deliberately
does not reopen by filename: rename, unlink or replacement could make the
path refer to another file. This observable limitation needs console and
debugger review before enabling the option by default.

Select `WINE_PS5_IMAGE_VIEW_FD_RELEASE=1`, or place exactly `1` with an
optional final newline in the prefix-local `pw_image_view_fd_release`.
An explicit environment value overrides the file. With 0880, an absent
setting in a valid prefix defaults on. An explicit `0` disables cleanup;
malformed settings, read errors, other open errors and an unavailable prefix
directory keep it off. The setting is read once and preserves `errno`;
non-PS5 builds always retain existing behavior. Matching-pair HL2, load and
600-second gameplay gates are pending for the combined default-on revision.

`python3 tests/test_wine_image_view_fds.py` compiles the actual patched
selection, release, census, mapping destruction, reuse and debugger-file
bodies with bounded fixture metadata. It checks 18 dependency rejection
guards, zero/mismatched view counts, multiple mapping owners and processes,
late debugger attachment, shared/data exclusions, metadata reuse, single
close and 17 strict configuration cases, including absent settings and
read/open errors. A real host `mmap` remains readable
after descriptor close. These are native contract checks, not a complete
Wine execution or a console resource-limit test. Run normally and with
clang ASan/UBSan; console validation must compare the same module pair with
selection off/on and ordinary image load/unload, section reuse, sharing,
HL2 and the fixed gameplay route.

`tools/build_wine_image_ordinary.py --out <artifact-directory>` prepares a
bounded x86 PE32 console fixture with kernel32-only imports. It copies only
its own executable to a unique filename, without overwriting existing files,
and maps that owned copy through ordinary Win32 APIs. Six case groups cover
later views from a live section after source-file close, retained views after
section close with a fresh section of the same file, multiple sections and
the last mapping owner, image sharing restrictions after section close, and
data/anonymous mapping lifetime. It checks committed readable view metadata
and its own image header/value, unmaps each successful view and deletes its
owned copy. The sharing case requests write access without writing bytes.
The fixture uses bounded handle counts and performs no resource-limit probe.
Results are written to `pw-image-ordinary.log`.

Compile and PE/import inspection do not execute Wine or establish lifetime
semantics. The console gate must compare the accepted pair and the candidate
pair with cleanup OFF/ON, keeping other settings fixed. Record all case
results, Wine-exit and the cleanup marker in the candidate-ON arm. This fixture
does not cover debugger attachment, writable shared image sections or every
file-delete/lock/async dependency; those remain separate contracts.
