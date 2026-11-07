<!-- Copyright (C) 2026 Carl-Philip Hänsch -->

# go-tdsstack

A bounded TDS 7.4 server transport for Go applications. It supplies packet framing,
TLS/login, RPC and prepared handle lifecycle, static read-only cursor snapshots,
result tokens and exact scalar wire codecs.

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

`Authenticate` returns application session state. `Execute` receives an untouched
batch string, optional untouched declaration string, and typed native parameters.
The application parses, validates, converts and binds these. Its callbacks must
finish all parallel row producers before returning. Cancellation covers the whole
request, including `Describe`. Pure `Describe` validates prepared or cursor shapes
without executing a statement. The library never constructs SQL transaction text.

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
