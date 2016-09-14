package etcdstore

import (
	"encoding/base32"
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/coreos/etcd/client"
	"golang.org/x/net/context"
	"sync"
	"fmt"
	"time"
)

var ErrNoDatabase = errors.New("no databases available")

// Amount of time for cookies/redis keys to expire.
var sessionExpire = 86400 * 30

// EtcdStore stores sessions in a redis backend.
type EtcdStore struct {
	Clientapi     	client.KeysAPI          // etcd client api interface
	Bucket        	string               	// bucket to store sessions in
	Codecs        	[]securecookie.Codec 	// session codecs
	Options       	*sessions.Options    	// default configuration
	DefaultMaxAge 	int 			// default TTL for a MaxAge == 0 session
	StoreMutex 	sync.RWMutex
}

// NewEtcdStore returns a new EtcdStore.
func NewEtcdStore(etcdaddr []string, bucket string, keyPairs ...[]byte) *EtcdStore {
	return &EtcdStore{
		Clientapi: func() client.KeysAPI {
				cfg := client.Config{
					Endpoints: etcdaddr,
					Transport: client.DefaultTransport,
				}
				c, err := client.New(cfg)
				if err != nil {
					return nil
				}
				kAPI := client.NewKeysAPI(c)
				return kAPI
				}(),
		Bucket: bucket,
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: sessionExpire,
		},
	}
}


// Get returns a session for the given name after adding it to the registry.
func (s *EtcdStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
func (s *EtcdStore) New(r *http.Request, name string) (*sessions.Session, error) {
	var err error
	session := sessions.NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...)
		if err == nil {
			err := s.load(session)
			session.IsNew = !(err == nil) // err == nil if session key already present in etcd
		}
	}
	return session, err
}

// Save adds a single session to the response.
func (s *EtcdStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	// Marked for deletion.
	if session.Options.MaxAge < 0 {
		if err := s.Delete(session); err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
	} else {
		// Build an alphanumeric key for the redis store.
		if session.ID == "" {
			session.ID = strings.TrimRight(base32.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(32)), "=")
		}
		if err := s.save(session); err != nil {
			return err
		}
		encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, s.Codecs...)
		if err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	}
	return nil
}

// save stores the session in Etcd.
func (s *EtcdStore) save(session *sessions.Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, s.Codecs...)
	if err != nil {
		return err
	}
	//var ctx = context.Background()
	ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Second)
	defer cancel()
	s.StoreMutex.Lock()
	key := "session_" + session.ID
	resp, err := s.Clientapi.Set(ctx, "/" + s.Bucket + "/" + key, encoded, nil)
	s.StoreMutex.Unlock()
	return err
}


// load reads the session from Etcd and updates the session.Values
func (s *EtcdStore) load(session *sessions.Session) error {

	//var ctx = context.Background()
	ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Second)
	defer cancel()
	s.StoreMutex.Lock()
	key := "session_" + session.ID
	resp, err := s.Clientapi.Get(ctx, "/" + s.Bucket + "/" + key, nil)
	s.StoreMutex.Unlock()
	if err != nil {
		return err
	}
	if err = securecookie.DecodeMulti(session.Name(), resp.Node.Value,
		&session.Values, s.Codecs...); err != nil {
		return err
	}

	return nil
}

// delete removes keys from Etcd if MaxAge<0
func (s *EtcdStore) Delete(session *sessions.Session) error {

	//var ctx = context.Background()
	ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Second)
	defer cancel()
	s.StoreMutex.Lock()
	key := "session_" + session.ID
	resp, err := s.Clientapi.Delete(ctx, "/" + s.Bucket + "/" + key, nil)
	s.StoreMutex.Unlock()
	return err
}