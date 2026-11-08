<!-- Copyright (C) 2026 Carl-Philip Hänsch -->

# go-tdsstack

A bounded TDS 7.4 server transport for Go applications. It supplies packet framing,
TLS/login, RPC and prepared handle lifecycle, static read-only cursor snapshots,
result tokens and exact scalar wire codecs.

`Handler.Bulk` accepts the TDS BulkLoadBCP stream following an application-owned
`INSERT BULK` command. The transport never parses that command or chooses a
destination. `BulkReader.Columns()` returns the explicit wire schema;
`BulkReader.Next()` returns one owned row at a time. Input uses packet-sized
backpressure with no whole-message or rowset buffer. Metadata is bounded to 4096
columns and each encoded row has a 64 MiB decoding budget.

The application must authorize the destination, validate the schema, own a
transaction, and roll back on every error. Commit only after `Next()` returns
`io.EOF`: this proves a valid DONE token and a clean message boundary. Truncation,
trailing bytes, error/abort flags and malformed values never yield successful
EOF. Returning from the handler without consuming the validated end is an error.
An early application rejection drains the remaining packets without buffering;
the next request retains its boundary. Bulk callbacks are request-local, serial,
and must not retain the reader. Supported scalar descriptors use the same exact
codecs as RPC values; legacy TEXT/IMAGE, XML/UDT tokens and unrecognized types fail.

The package does not parse SQL, infer SQL types, own database transactions, or bind
application parameters. It uses native Go data and opaque application sessions.
Applications supply explicit column descriptors before rows, even for empty and
all-NULL results. Parameters retain their wire descriptors, including typed NULL.

```go
server := &tds.Server{
    Database: "example",
    Handler: tds.Handler{
        Authenticate: authenticate,
        Execute: execute,
        Describe: describe,
        Reset: reset,
        Close: closeSession,
    },
}
listener, err := net.Listen("tcp", ":1433")
if err != nil {
    return err
}
return server.Serve(listener)
```

`Authenticate` receives `Login.HostName` and `Login.AppName` exactly as supplied
by the client in LOGIN7, including empty strings. These are untrusted client
labels, not server configuration or authenticated identity. Applications may
retain them in their connection state; the transport does not interpret them.

`Authenticate` returns application session state. `Execute` receives an untouched
batch string, optional untouched declaration string, and typed native parameters.
The application parses, validates, converts and binds these. Its callbacks must
finish all parallel row producers before returning. Cancellation covers the whole
request, including `Describe`. Pure `Describe` validates prepared or cursor shapes
without executing a statement. The library never constructs SQL transaction text.

`Server.Collation` optionally supplies the five-byte default session collation
announced by ENVCHANGE type 7 during successful login. The transport does not
choose an SQL collation or infer it from result rows; the all-zero default omits
the announcement for compatibility. Clients need this default when encoding ANSI
or SQL_VARIANT RPC parameters before any result metadata has been received.

`Metadata` handles named procedure requests in the frontend. `Transaction` receives
explicit wire actions. A requested transaction successor invokes the completion
callback first and invokes begin only if completion succeeds. `BeginRequest` is an
optional application scope boundary. `Reset` replaces application pooling state;
`Close` releases it. The server never reads application session keys.

A result begins with `Fields([]Column)`, followed by `Row([]any)` and optional
`Done(Completion)`. `Completion` explicitly communicates row counts, database
changes, transaction state and further results. A handler with one result can omit
`Done`; the transport finishes it with the emitted row count. Parallel row callbacks
are serialized only at this output boundary. Each row is completely validated
before publishing its ROW token, so malformed payloads cannot swallow an error token.

Use `int64`, `float64`, `bool`, `string`, `[]byte`, or `nil` for ordinary wire values.
Standalone GUIDTYPE (`0x24`, Size 16) uses exactly sixteen canonical UUID bytes
in `[]byte`, or `nil` for NULL. The codec owns the TDS mixed-endian field order;
UUID text parsing and formatting remain application concerns. Metadata always
retains Size 16, including NULL; non-NULL payload lengths other than 16 fail.
Incoming typed GUID NULL also accepts the protocol's zero-width descriptor;
that width never admits a non-NULL value.
`Decimal` carries an unscaled canonical integer string; no binary floating point
conversion occurs. `Temporal` carries day ordinal, wire clock units and original
offset minutes. These are transient protocol payloads, not persistent SQL types.
The application performs scale, precision, calendar and implicit-cast semantics.

`Variant{Type: ..., Value: ...}` supplies explicit per-value base metadata for
SQL_VARIANT (column/parameter kind `0x62`, maximum size 8016 bytes). Its base
`Type` uses the ordinary nullable descriptors; the codec translates them to the
fixed base tokens specified by MS-TDS 2.2.5.5.4. NULL is an outer `nil`, not a
Variant wrapping nil. Supported bases are integer, bit, float, money, decimal,
date/time and bounded character/binary types. Decimal variant magnitudes always
occupy 16 bytes while retaining their declared precision and scale. Nested
variants, GUID, MAX/LOB and unrecognized bases fail explicitly. RPC decoding
retains the base descriptor; cursor snapshots clone the owned scalar payload.

RPC metadata hints `fNoMetaData` and `fReuseMetaData` are accepted. Ordinary
requests always return complete column metadata, including first execution;
static cursor fetch may omit its already-advertised immutable schema when
requested. Recompile and reserved option bits remain unsupported.

Prepared handles retain only opaque text and declarations. Cursor snapshots retain
only bounded, cloned native payloads. Neither retains a query context, transaction,
application session, callback closure, planner or storage object. Newly created
handles become visible only after successful response publication. Failed or
cancelled publication removes them.

Explicitly unsupported: MARS, integrated authentication, password changes,
RESETCONNECTIONSKIPTRAN, nonstatic/updatable cursors, arbitrary output statement
parameters, unsupported code pages and unrecognized wire types. Frontends determine
which SQL grammar and type domains they support.

Verification:

```sh
go test -race ./...
go vet ./...
```

Tests include released client TCP/TLS/login/typed-result interoperability, exact
38-digit coefficient and 100ns/offset goldens, typed NULL, malformed packets,
prepared lifecycle and pure describe, static cursor fetch positions and snapshots,
transaction successors, attention/reuse, concurrent rows and failed publication.
