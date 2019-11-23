package main

import (
	"bytes"
	"context"
	"errors"

	"github.com/aschlosberg/myaspire/argon2"
	pb "github.com/aschlosberg/myaspire/awscryptod/proto"
	log "github.com/golang/glog"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *service) HashPassword(ctx context.Context, req *pb.HashPasswordRequest) (*pb.HashPasswordResponse, error) {
	hash, err := argon2.Hash(req.Password)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "hashing password: %v", err)
	}
	return &pb.HashPasswordResponse{
		Hash: hash,
	}, nil
}

var (
	bcryptA  = []byte(`$2a$`)
	bcryptB  = []byte(`$2b$`)
	bcryptX  = []byte(`$2x$`)
	bcryptY  = []byte(`$2y$`)
	argon2id = []byte(`$argon2id$`)
	argon2i  = []byte(`$argon2i$`)
)

func (s *service) CheckPassword(ctx context.Context, req *pb.CheckPasswordRequest) (*pb.CheckPasswordResponse, error) {
	var match, updateIfMatch bool
	var reason string

	switch {
	case bytes.HasPrefix(req.Hash, bcryptA):
		fallthrough
	case bytes.HasPrefix(req.Hash, bcryptB):
		fallthrough
	case bytes.HasPrefix(req.Hash, bcryptX):
		fallthrough
	case bytes.HasPrefix(req.Hash, bcryptY):
		match = bcrypt.CompareHashAndPassword(req.Hash, req.Password) == nil
		updateIfMatch = true
	case bytes.HasPrefix(req.Hash, argon2id):
		updateIfMatch = true
		fallthrough
	case bytes.HasPrefix(req.Hash, argon2i):
		var err error
		match, err = argon2.Compare(req.Hash, req.Password)
		var e argon2.Error
		if errors.As(err, &e) {
			reason = err.Error()
		}
	}

	resp := &pb.CheckPasswordResponse{
		Match:       match,
		DebugReason: reason,
		Update:      match && updateIfMatch,
	}
	if resp.Update {
		updated, err := s.HashPassword(ctx, &pb.HashPasswordRequest{Password: req.Password})
		// We shouldn't block a user from logging in merely because we couldn't
		// update the hash.
		if err != nil {
			log.Errorf("Update password: %v", err)
			resp.DebugReason = err.Error()
		} else {
			resp.Updated = updated.Hash
		}
	}
	return resp, nil
}
