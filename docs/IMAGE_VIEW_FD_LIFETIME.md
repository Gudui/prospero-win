# Image-view file descriptor lifetime

Status: experimental, default off. Native fixture checks pass; console
behavior and resource savings are not yet validated.

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
An explicit environment value overrides the file. The setting is read
once and defaults off; non-PS5 builds always retain existing behavior.

`python3 tests/test_wine_image_view_fds.py` compiles the actual patched
selection, release, census, mapping destruction, reuse and debugger-file
bodies with bounded fixture metadata. It checks 18 dependency rejection
guards, zero/mismatched view counts, multiple mapping owners and processes,
late debugger attachment, shared/data exclusions, metadata reuse, single
close and 15 strict configuration cases. A real host `mmap` remains readable
after descriptor close. These are native contract checks, not a complete
Wine execution or a console resource-limit test. Run normally and with
clang ASan/UBSan; console validation must compare the same module pair with
selection off/on and ordinary image load/unload, section reuse, sharing,
HL2 and the fixed gameplay route.
