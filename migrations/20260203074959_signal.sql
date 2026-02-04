-- Add migration script here

create table if not exists kyber_pre_key (
    id integer primary key AUTOINCREMENT,
    keyId integer,
    record text,
    used bool Not NULL DEFAULT false,
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

create table if not exists kyber_singed_ids (
    id integer primary key AUTOINCREMENT,
    kyberId integer,
    signedId integer,
    baseKey text,
    createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);