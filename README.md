# Etcd store

A session store backend for [gorilla/sessions](http://www.gorillatoolkit.org/pkg/sessions) - [src](https://github.com/gorilla/sessions) using [Etcd](https://coreos.com/etcd/).

## Requirements

Depends on etcd client [Etcd-client](https://github.com/coreos/etcd/tree/master/client).

## Installation

    go get github.com/shampur/etcdstore

## Documentation

Available on [godoc.org](http://www.godoc.org/github.com/shampur/etcdstore).

See http://www.gorillatoolkit.org/pkg/sessions for full documentation on underlying interface.

### Example

    // Fetch new store.
	addrs := []string{"127.0.0.1:2379"}
	store := NewEtcdStore([]string{"http://127.0.0.1:2379"}, "session-name", []byte("something-very-secret")),

    // Get a session.
	session, err := store.Get(req, "session-key")
	if err != nil {
        log.Error(err.Error())
    }

    // Add a value.
    session.Values["foo"] = "bar"

    // Save.
    if err = sessions.Save(req, rsp); err != nil {
        t.Fatalf("Error saving session: %v", err)
    }

    // Delete session.
    session.Options.MaxAge = -1
    if err = sessions.Save(req, rsp); err != nil {
        t.Fatalf("Error saving session: %v", err)
    }

