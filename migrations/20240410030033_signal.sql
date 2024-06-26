-- Add migration script here
create table if not exists identity (
        id integer primary key AUTOINCREMENT,
        nextPrekeyId integer,
        registrationId integer,
        device integer,
        address text,
        privateKey text,
        publicKey text,
        createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

create table if not exists ratchet_key (
    id integer primary key AUTOINCREMENT,
    aliceRatchetKeyPublic text,
    address text,
    device integer,
    roomId integer,
    bobRatchetKeyPrivate text,
    ratcheKeyHash text,
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

alter table ratchet_key rename column ratcheKeyHash to ratchetKeyHash;

create table if not exists session (
    id integer primary key AUTOINCREMENT,
    aliceSenderRatchetKey text,
    address text,
    device integer,
    record text,
    bobSenderRatchetKey text,
    bobAddress text,
    aliceAddresses text,
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

create table if not exists signed_key (
    id integer primary key AUTOINCREMENT,
    keyId integer,
    record text,
    used bool Not NULL DEFAULT false,
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

create table if not exists pre_key (
    id integer primary key AUTOINCREMENT,
    keyId integer,
    record text,
    used bool Not NULL DEFAULT false,
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);