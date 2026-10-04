/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Public Wine NtCreateMutant excerpt for a bounded native creation fixture.
 * Copyright 1996, 1997, 1998 Marcus Meissner
 * Copyright 1997, 1999 Alexandre Julliard
 * Copyright 1999, 2000 Juergen Schmied
 * Copyright 2003 Eric Pouech
 * Pre-0830 function SHA256 db62cc9ac6b44161d13c6a4a29229d63733bd4296267cd4cb11125b91898d71f
 */

NTSTATUS WINAPI NtCreateMutant( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                BOOLEAN owned )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, owned %u\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", owned );

    *handle = 0;
    if ((ret = wine_server_alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_mutex )
    {
        req->access  = access;
        req->owned   = owned;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        server_clear_fast_mutex_hint( wine_server_ptr_handle( reply->handle ) );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}
