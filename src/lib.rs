// SPDX-License-Identifier: AGPL-3.0-only
//! Implementations for stores defined in [super::traits].

pub use libsignal_protocol;

use async_trait::async_trait;
use futures_util::StreamExt;
use libsignal_protocol::*;
use log::info;
use rand::random;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
pub type Result<T> = std::result::Result<T, SignalProtocolError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalIdentitie {
    pub next_prekey_id: Option<u32>,
    pub registration_id: Option<u32>,
    pub address: String,
    pub device: u32,
    pub private_key: Option<String>,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalRatchetKey {
    pub alice_ratchet_key_public: String,
    pub room_id: u32,
    pub address: String,
    pub device: String,
    pub bob_ratchet_key_private: String,
    pub ratchet_key_hash: Option<String>,
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone)]
pub struct SignalSession {
    pub alice_sender_ratchet_key: Option<String>,
    pub address: String,
    pub device: u32,
    pub bob_sender_ratchet_key: Option<String>,
    pub record: String,
    pub bob_address: Option<String>,
    pub alice_addresses: Option<String>,
}

#[macro_use]
extern crate anyhow;
extern crate async_trait;
extern crate log;
extern crate serde;
pub use sqlx;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::Row;
use sqlx::SqlitePool;

#[derive(Debug, Clone)]
pub struct LitePool {
    db: SqlitePool,
    tables: Tables,
}

impl LitePool {
    pub async fn new(db: SqlitePool, tables: Tables) -> anyhow::Result<LitePool> {
        tables.check()?;

        let this = Self { db, tables };
        this.migrate().await?;

        Ok(this)
    }

    /// try open tables
    pub async fn migrate(&self) -> anyhow::Result<()> {
        self.init().await?;
        Ok(())
    }

    /// https://docs.rs/sqlx-sqlite/0.7.1/sqlx_sqlite/struct.SqliteConnectOptions.html#impl-FromStr-for-SqliteConnectOptions
    pub async fn open(dbpath: &str, tables: Tables) -> anyhow::Result<LitePool> {
        let opts = dbpath
            .parse::<SqliteConnectOptions>()?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            // prevent other thread open it
            .locking_mode(sqlx::sqlite::SqliteLockingMode::Normal)
            // or normal
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);

        info!("SqlitePool open: {:?}", opts);
        let db = sqlx::sqlite::SqlitePoolOptions::new()
            // .max_connections(1)
            .connect_with(opts)
            .await?;

        Self::new(db, tables).await
    }

    pub fn database(&self) -> &SqlitePool {
        &self.db
    }

    pub fn tables(&self) -> &Tables {
        &self.tables
    }

    pub async fn init(&self) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.db)
            .await
            .map_err(|e| format_err!("run sqlite migrations failed: {}", e))?;

        Ok(())
    }

    #[inline]
    pub fn definition_identity(&self) -> &'static str {
        self.tables.identity
    }

    #[inline]
    pub fn definition_ratchet_key(&self) -> &'static str {
        self.tables.ratchet_key
    }

    #[inline]
    pub fn definition_session(&self) -> &'static str {
        self.tables.session
    }

    #[inline]
    pub fn definition_signed_key(&self) -> &'static str {
        self.tables.signed_key
    }

    #[inline]
    pub fn definition_pre_key(&self) -> &'static str {
        self.tables.pre_key
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tables {
    identity: &'static str,
    ratchet_key: &'static str,
    session: &'static str,
    signed_key: &'static str,
    pre_key: &'static str,
}

impl Default for Tables {
    fn default() -> Self {
        Self {
            identity: "identity",
            ratchet_key: "ratchet_key",
            session: "session",
            signed_key: "signed_key",
            pre_key: "pre_key",
        }
    }
}

impl Tables {
    pub fn check(&self) -> Result<()> {
        let strs = [
            self.identity,
            self.ratchet_key,
            self.session,
            self.signed_key,
            self.pre_key,
        ];
        let mut names = strs.iter().filter(|s| !s.is_empty()).collect::<Vec<_>>();
        if names.len() != strs.len() {
            SignalProtocolError::InvalidArgument("empty table name".to_string());
        }

        names.dedup();
        if names.len() != strs.len() {
            SignalProtocolError::InvalidArgument("duplicate table name".to_string());
        }

        Ok(())
    }
}

/// Reference implementation of [traits::IdentityKeyStore].
#[derive(Clone)]
pub struct KeyChatIdentityKeyStore {
    pool: LitePool,
    key_pair: IdentityKeyPair,
    registration_id: u32,
}

impl KeyChatIdentityKeyStore {
    /// get identity by address
    pub async fn get_identity_by_address(
        &self,
        address: &str,
        device_id: &str,
    ) -> Result<Option<SignalIdentitie>> {
        let sql = format!("select nextPrekeyId, registrationId, address, device, privateKey, publicKey from {} where address = ? and device = ? order by id desc limit 1", self.pool.definition_identity());
        let identity = sqlx::query(&sql)
            .bind(address)
            .bind(device_id)
            .fetch_optional(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("get_identity_by_address execute: {}", e).to_string(),
                )
            })?;
        if identity.is_none() {
            return Ok(None);
        }
        let row = identity.unwrap();
        let info = SignalIdentitie {
            next_prekey_id: row.get(0),
            registration_id: row.get(1),
            address: row.get(2),
            device: u32::try_from(row.get::<'_, i64, _>(3)).map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("get device from identity: {}", e).to_string(),
                )
            })?,
            private_key: row.get(4),
            public_key: row.get(5),
        };

        Ok(Some(info))
    }

    pub fn get_identity_key_pair_keys(
        &self,
        public_key: &str,
        private_key: &str,
    ) -> Result<IdentityKeyPair> {
        let public_key_vec = decode_str_to_bytes(public_key).map_err(|e| {
            SignalProtocolError::InvalidArgument(
                format_err!("decode public key error: {}", e).to_string(),
            )
        })?;
        let private_key_vec = decode_str_to_bytes(private_key).map_err(|e| {
            SignalProtocolError::InvalidArgument(
                format_err!("decode private key error: {}", e).to_string(),
            )
        })?;
        let identity = IdentityKey::decode(&public_key_vec)?;
        let private_key = PrivateKey::deserialize(&private_key_vec)?;
        let id_key_pair = IdentityKeyPair::new(identity, private_key);
        Ok(id_key_pair)
    }

    pub async fn get_identity_key_pair_bak(
        &self,
        address: &str,
        device_id: &str,
    ) -> Result<IdentityKeyPair> {
        let identity = self
            .get_identity_by_address(address, device_id)
            .await?
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument("identity not found".to_string())
            })?;

        let private_key = identity.private_key.ok_or_else(|| {
            SignalProtocolError::InvalidArgument("private_key not found".to_string())
        })?;

        self.get_identity_key_pair_keys(&identity.public_key, &private_key)
    }

    pub async fn get_local_registration_id_bak(
        &self,
        address: &str,
        device_id: &str,
    ) -> Result<u32> {
        let identity = self.get_identity_by_address(address, device_id).await?;
        let registration_id = identity
            .ok_or_else(|| SignalProtocolError::InvalidArgument("Identity not found".to_string()))?
            .registration_id
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument("Registration ID not found".to_string())
            })?;
        Ok(registration_id)
    }

    /// insert identity
    pub async fn insert_identity(&self, identity: SignalIdentitie) -> Result<()> {
        let sql = format!("INSERT INTO {} (nextPrekeyId, registrationId, address, device, privateKey, publicKey) values (?, ?, ?, ?, ?, ?)", self.pool.definition_identity());
        sqlx::query(&sql)
            .bind(identity.next_prekey_id)
            .bind(identity.registration_id)
            .bind(identity.address)
            .bind(identity.device)
            .bind(identity.private_key)
            .bind(identity.public_key)
            .execute(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute insert_identity error: {}", e).to_string(),
                )
            })?;

        Ok(())
    }

    pub async fn create_identity(
        &self,
        address: &ProtocolAddress,
        id_key_pair: &IdentityKeyPair,
    ) -> Result<bool> {
        let name = address.name();
        let device_id = address.device_id();
        let identity = self
            .get_identity_by_address(name, &device_id.to_string())
            .await?;
        if identity.is_none() {
            self.insert_identity(SignalIdentitie {
                next_prekey_id: None,
                registration_id: None,
                address: name.to_owned(),
                device: device_id.into(),
                private_key: Some(hex::encode(id_key_pair.public_key().serialize())),
                public_key: hex::encode(id_key_pair.private_key().serialize()),
            })
            .await?;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn get_identity_public_key(&self, public_key: &str) -> Result<IdentityKey> {
        let public_key_vec: Vec<u8> = decode_str_to_bytes(public_key).map_err(|e| {
            SignalProtocolError::InvalidArgument(
                format_err!("serde public key error: {}", e).to_string(),
            )
        })?;
        let identity = IdentityKey::decode(&public_key_vec)?;
        Ok(identity)
    }

    pub async fn delete_identity(&self, address: &str) -> Result<bool> {
        let sql = format!(
            "delete from {} where address = ?",
            self.pool.definition_identity()
        );
        let result = sqlx::query(&sql)
            .bind(address)
            .execute(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute delete_identity error: {}", e).to_string(),
                )
            })?;
        let cnt = result.rows_affected();
        if cnt > 0 {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for KeyChatIdentityKeyStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        Ok(self.key_pair)
    }

    async fn get_local_registration_id(&self) -> Result<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool> {
        let name = address.name();
        let device_id = address.device_id();
        let mut signal_identity = self
            .get_identity_by_address(name, &device_id.to_string())
            .await?;
        // new key
        if signal_identity.as_ref().is_none() {
            self.insert_identity(SignalIdentitie {
                address: name.to_string(),
                device: device_id.into(),
                public_key: hex::encode(identity.serialize()),
                private_key: None,
                registration_id: None,
                next_prekey_id: None,
            })
            .await?;
            return Ok(false);
        }
        // overwrite
        if self.get_identity_public_key(
            &signal_identity
                .as_ref()
                .ok_or_else(|| {
                    SignalProtocolError::InvalidArgument("signal_identity not found".to_string())
                })?
                .public_key,
        )? != *identity
        {
            signal_identity
                .as_mut()
                .ok_or_else(|| {
                    SignalProtocolError::InvalidArgument("signal_identity not found".to_string())
                })?
                .public_key = hex::encode(identity.serialize());
            self.insert_identity(signal_identity.ok_or_else(|| {
                SignalProtocolError::InvalidArgument("signal_identity not found".to_string())
            })?)
            .await?;
            return Ok(true);
        }
        // same key
        Ok(false)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool> {
        let their_address = address.name();
        let device_id = address.device_id().to_string();
        let signal_identity = self
            .get_identity_by_address(their_address, &device_id)
            .await?;
        match direction {
            Direction::Sending => {
                if signal_identity.is_none() {
                    return Ok(true);
                }
                if *identity
                    != self.get_identity_public_key(
                        &signal_identity
                            .as_ref()
                            .ok_or_else(|| {
                                SignalProtocolError::InvalidArgument(
                                    "signal_identity not found".to_string(),
                                )
                            })?
                            .public_key,
                    )?
                {
                    return Ok(false);
                }
                return Ok(true);
            }
            Direction::Receiving => {
                return Ok(true);
            }
        }
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        let name = address.name();
        let device_id = address.device_id().to_string();
        let identity = self.get_identity_by_address(name, &device_id).await?;
        if identity.is_none() {
            return Ok(None);
        }
        let id_key = self.get_identity_public_key(
            &identity
                .ok_or_else(|| {
                    SignalProtocolError::InvalidArgument("identity not found".to_string())
                })?
                .public_key,
        )?;
        Ok(Some(id_key))
    }
}

/// Reference implementation of [traits::SessionStore].
#[derive(Clone)]
pub struct KeyChatSessionStore {
    pool: LitePool,
}

impl KeyChatSessionStore {
    /// store session return update flag and alice_addr_previous
    pub async fn store_session_bak(
        &self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        my_receiver_address: Option<&str>,
        to_receiver_address: Option<&str>,
        sender_ratchet_key: Option<&str>,
    ) -> Result<(u32, Option<Vec<String>>)> {
        let mut flag: u32 = 0;
        let mut alice_addrs_pre: Option<Vec<String>> = None;
        let name = address.name();
        let device_id = &address.device_id().to_string();
        let mut session = self.get_session(name, device_id).await?;
        if session.is_none() {
            self.insert_session(
                address,
                record,
                my_receiver_address,
                to_receiver_address,
                sender_ratchet_key,
            )
            .await?;
            return Ok((0, alice_addrs_pre));
        }
        let record_to_str =
            hex::encode(record.serialize().map_err(|_| {
                SignalProtocolError::InvalidArgument("record not found".to_string())
            })?);
        let ss = session
            .as_mut()
            .ok_or_else(|| SignalProtocolError::InvalidArgument("session not found".to_string()))?;
        if ss.record == record_to_str {
            return Ok((1, alice_addrs_pre));
        }
        ss.record = record_to_str;

        if to_receiver_address.is_some() {
            if ss.bob_sender_ratchet_key.is_none()
                || sender_ratchet_key != ss.bob_sender_ratchet_key.as_deref()
            {
                ss.bob_address = Some(
                    to_receiver_address
                        .ok_or_else(|| {
                            SignalProtocolError::InvalidArgument(
                                "to_receiver_address not found".to_string(),
                            )
                        })?
                        .to_string(),
                );
                ss.bob_sender_ratchet_key = Some(
                    sender_ratchet_key
                        .ok_or_else(|| {
                            SignalProtocolError::InvalidArgument(
                                "sender_ratchet_key not found".to_string(),
                            )
                        })?
                        .to_string(),
                );
                flag = 2;
                self.update_session(false, ss).await?;
            }
        }
        if my_receiver_address.is_some() {
            if ss.alice_addresses.is_none() {
                ss.alice_sender_ratchet_key = Some(
                    sender_ratchet_key
                        .ok_or_else(|| {
                            SignalProtocolError::InvalidArgument(
                                "sender_ratchet_key not found".to_string(),
                            )
                        })?
                        .to_string(),
                );
                ss.alice_addresses = Some(
                    my_receiver_address
                        .ok_or_else(|| {
                            SignalProtocolError::InvalidArgument(
                                "my_receiver_address not found".to_string(),
                            )
                        })?
                        .to_string(),
                );
                flag = 3;
            } else if sender_ratchet_key != ss.alice_sender_ratchet_key.as_deref() {
                ss.alice_sender_ratchet_key = Some(
                    sender_ratchet_key
                        .ok_or_else(|| {
                            SignalProtocolError::InvalidArgument(
                                "sender_ratchet_key not found".to_string(),
                            )
                        })?
                        .to_string(),
                );
                let alice_addresses2 = ss.alice_addresses.as_ref().ok_or_else(|| {
                    SignalProtocolError::InvalidArgument("alice_addresses not found".to_string())
                })?;
                let mut list: Vec<&str> = alice_addresses2.split(',').collect();
                list.push(my_receiver_address.ok_or_else(|| {
                    SignalProtocolError::InvalidArgument(
                        "my_receiver_address not found".to_string(),
                    )
                })?);
                ss.alice_addresses = Some(list.join(","));
                flag = 4;
            }
            // only get alice addrs previous when update
            alice_addrs_pre = Some(self.get_alice_addrs_by_identity(name, device_id).await?);
            self.update_session(true, ss).await?;
        }
        Ok((flag, alice_addrs_pre))
    }

    pub async fn update_session(&self, is_alice: bool, session: &SignalSession) -> Result<()> {
        if is_alice {
            let sql = format!("update {} set aliceSenderRatchetKey = ?, aliceAddresses = ?, record = ? where address = ? and device = ?", self.pool.definition_session());
            sqlx::query(&sql)
                .bind(&session.alice_sender_ratchet_key)
                .bind(&session.alice_addresses)
                .bind(&session.record)
                .bind(&session.address)
                .bind(session.device)
                .execute(&self.pool.db)
                .await
                .map_err(|e| {
                    SignalProtocolError::InvalidArgument(
                        format_err!("execute update_session error: {}", e).to_string(),
                    )
                })?;
        } else {
            let sql = format!("update {} set bobSenderRatchetKey = ?, bobAddress = ?, record = ? where address = ? and device = ?", self.pool.definition_session());
            sqlx::query(&sql)
                .bind(&session.bob_sender_ratchet_key)
                .bind(&session.bob_address)
                .bind(&session.record)
                .bind(&session.address)
                .bind(session.device)
                .execute(&self.pool.db)
                .await
                .map_err(|e| {
                    SignalProtocolError::InvalidArgument(
                        format_err!("execute update_session error: {}", e).to_string(),
                    )
                })?;
        }
        Ok(())
    }

    /// insert session
    pub async fn insert_session(
        &self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        my_receiver_address: Option<&str>,
        to_receiver_address: Option<&str>,
        sender_ratchet_key: Option<&str>,
    ) -> Result<()> {
        if my_receiver_address.is_none() && to_receiver_address.is_none() {
            let sql = format!(
                "INSERT INTO {} (address, device, record) values (?, ?, ?)",
                self.pool.definition_session()
            );
            sqlx::query(&sql)
                .bind(address.name())
                .bind(address.device_id().to_string())
                .bind(hex::encode(record.serialize().map_err(|_| {
                    SignalProtocolError::InvalidArgument("record serialize error".to_string())
                })?))
                .execute(&self.pool.db)
                .await
                .map_err(|e| {
                    SignalProtocolError::InvalidArgument(
                        format_err!("execute insert_session error: {}", e).to_string(),
                    )
                })?;
        }
        if my_receiver_address.is_some() {
            let sql = format!("INSERT INTO {} (address, device, record, aliceSenderRatchetKey, aliceAddresses)  values (?, ?, ?, ?, ?)", self.pool.definition_session());
            sqlx::query(&sql)
                .bind(address.name())
                .bind(address.device_id().to_string())
                .bind(hex::encode(record.serialize().map_err(|_| {
                    SignalProtocolError::InvalidArgument("record serialize error".to_string())
                })?))
                .bind(sender_ratchet_key)
                .bind(my_receiver_address)
                .execute(&self.pool.db)
                .await
                .map_err(|e| {
                    SignalProtocolError::InvalidArgument(
                        format_err!("execute insert_session error: {}", e).to_string(),
                    )
                })?;
        }
        if to_receiver_address.is_some() {
            let sql = format!("INSERT INTO {} (address, device, record, bobSenderRatchetKey, bobAddress)  values (?, ?, ?, ?, ?)", self.pool.definition_session());
            sqlx::query(&sql)
                .bind(address.name())
                .bind(address.device_id().to_string())
                .bind(hex::encode(record.serialize().map_err(|_| {
                    SignalProtocolError::InvalidArgument("record serialize error".to_string())
                })?))
                .bind(sender_ratchet_key)
                .bind(to_receiver_address)
                .execute(&self.pool.db)
                .await
                .map_err(|e| {
                    SignalProtocolError::InvalidArgument(
                        format_err!("execute insert_session error: {}", e).to_string(),
                    )
                })?;
        }

        Ok(())
    }

    pub async fn get_session(
        &self,
        address: &str,
        device_id: &str,
    ) -> Result<Option<SignalSession>> {
        let sql = format!("select aliceSenderRatchetKey, address, device, record, bobSenderRatchetKey, bobAddress, aliceAddresses from {} where address = ? and device = ? order by id desc limit 1", self.pool.definition_session());
        let result = sqlx::query(&sql)
            .bind(address)
            .bind(device_id)
            .fetch_optional(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute get_session error: {}", e).to_string(),
                )
            })?;

        if result.is_none() {
            return Ok(None);
        }
        let row = result.unwrap();
        let session = SignalSession {
            alice_sender_ratchet_key: row.get(0),
            address: row.get(1),
            device: u32::try_from(row.get::<'_, i64, _>(2)).map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute get device from session error: {}", e).to_string(),
                )
            })?,
            record: row.get(3),
            bob_sender_ratchet_key: row.get(4),
            bob_address: row.get(5),
            alice_addresses: row.get(6),
        };
        Ok(Some(session))
    }

    pub async fn get_all_alice_addrs(&self) -> Result<Vec<String>> {
        let sql = format!(
            "select aliceAddresses from {}",
            self.pool.definition_session()
        );
        let mut iter = sqlx::query(&sql).fetch(&self.pool.db);
        let mut alice_addrs = Vec::new();

        while let Some(it) = iter.next().await {
            let it = it.map_err(|e| SignalProtocolError::InvalidArgument(format!("get_all_alice_addrs fetch error“: {}", e)))?;
            let address = it.get::<'_, Option<String>, _>(0);
            if let Some(address) = address {
                alice_addrs.push(address)
            };
        }
        Ok(alice_addrs)
    }

    pub async fn get_alice_addrs_by_identity(
        &self,
        address: &str,
        device_id: &str,
    ) -> Result<Vec<String>> {
        let sql = format!("select aliceAddresses from {} where address = ? and device = ? order by id desc limit 1", self.pool.definition_session());
        let result = sqlx::query(&sql)
            .bind(address)
            .bind(device_id)
            .fetch_optional(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute get_alice_addrs_by_identity error: {}", e).to_string(),
                )
            })?;
        let mut alice_addrs = Vec::new();
        if result.is_none() {
            return Ok(alice_addrs);
        }
        let row = result.unwrap();

        let address = row.get::<'_, Option<String>, _>(0);
        // aliceAddresses is hex binary combine
        if let Some(address) = address {
            alice_addrs.push(address)
        };

        Ok(alice_addrs)
    }

    pub async fn session_contain_alice_addr(
        &self,
        sub_address: &str,
    ) -> Result<Option<SignalSession>> {
        let sql = format!("select aliceSenderRatchetKey, address, device, record, bobSenderRatchetKey, bobAddress, aliceAddresses from {} where instr(aliceAddresses, ?) order by id desc limit 1", self.pool.definition_session());
        let result = sqlx::query(&sql)
            .bind(sub_address)
            .fetch_optional(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute session_contain_alice_addr error: {}", e).to_string(),
                )
            })?;
        if result.is_none() {
            return Ok(None);
        }
        let row = result.unwrap();
        let session = SignalSession {
            alice_sender_ratchet_key: row.get(0),
            address: row.get(1),
            device: u32::try_from(row.get::<'_, i64, _>(3)).map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute get device from session error: {}", e).to_string(),
                )
            })?,
            record: row.get(3),
            bob_sender_ratchet_key: row.get(4),
            bob_address: row.get(5),
            alice_addresses: row.get(6),
        };

        Ok(Some(session))
    }

    pub async fn update_alice_addr(
        &self,
        address: &str,
        device_id: &str,
        alice_addr: &str,
    ) -> Result<bool> {
        let sql = format!(
            "update {} set aliceAddresses = ? where address = ? and device = ? ",
            self.pool.definition_session()
        );
        let result = sqlx::query(&sql)
            .bind(alice_addr)
            .bind(address)
            .bind(device_id)
            .execute(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute update_alice_addr error: {}", e).to_string(),
                )
            })?;
        let cnt = result.rows_affected();
        if cnt > 0 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn delete_session(&self, address: &ProtocolAddress) -> Result<bool> {
        let name = address.name();
        let device_id = &address.device_id().to_string();
        let session = self.get_session(name, device_id).await?;
        if session.is_some() {
            let sql = format!(
                "delete from {} where address = ? and device = ?",
                self.pool.definition_session()
            );
            let result = sqlx::query(&sql)
                .bind(name)
                .bind(device_id)
                .execute(&self.pool.db)
                .await
                .map_err(|e| {
                    SignalProtocolError::InvalidArgument(
                        format_err!("execute delete_session error: {}", e).to_string(),
                    )
                })?;
            let cnt = result.rows_affected();
            if cnt > 0 {
                return Ok(true);
            } else {
                return Ok(false);
            }
        }
        Ok(false)
    }

    pub async fn delete_session_by_device_id(&self, device_id: u32) -> Result<bool> {
        let sql = format!(
            "delete from {} where device = ?",
            self.pool.definition_session()
        );
        let result = sqlx::query(&sql)
            .bind(device_id)
            .execute(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute delete_session_by_device_id error: {}", e).to_string(),
                )
            })?;
        let cnt = result.rows_affected();
        if cnt > 0 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn load_session_bak(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>> {
        let name = address.name();
        let device_id = &address.device_id().to_string();
        let session = self.get_session(name, device_id).await?;
        match session {
            Some(session) => {
                let record_vec = decode_str_to_bytes(&session.record).map_err(|e| {
                    SignalProtocolError::InvalidArgument(format!("serde record error: {}", e))
                })?;
                let record = SessionRecord::deserialize(&record_vec)?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    pub async fn contains_session(&self, address: &ProtocolAddress) -> Result<bool> {
        let name = address.name();
        let device_id = &address.device_id().to_string();
        let session = self.get_session(name, device_id).await?;
        if session.is_none() {
            return Ok(false);
        }
        let session_record = self.load_session_bak(address).await?;
        if session_record.is_none() {
            return Ok(false);
        }
        // CIPHERTEXT_MESSAGE_CURRENT_VERSION is 3
        let ciphertext_message_current_version = 3;
        let session_record = session_record.unwrap();
        let flag = session_record
            .has_usable_sender_chain(SystemTime::now())
            .map_err(|_| {
                SignalProtocolError::InvalidArgument("session_record not found".to_string())
            })?
            && session_record.session_version().map_err(|_| {
                SignalProtocolError::InvalidArgument("session_version not found".to_string())
            })? == ciphertext_message_current_version;
        Ok(flag)
    }
}

#[async_trait(?Send)]
impl SessionStore for KeyChatSessionStore {
    /// Look up the session corresponding to `address`.
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        let session = self.load_session_bak(address).await?;
        Ok(session)
    }
    /// Set the entry for `address` to the value of `record`.
    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        my_receiver_address: Option<String>,
        to_receiver_address: Option<String>,
        sender_ratchet_key: Option<String>,
    ) -> Result<(u32, Option<Vec<String>>)> {
        let result = self
            .store_session_bak(
                address,
                record,
                my_receiver_address.as_deref(),
                to_receiver_address.as_deref(),
                sender_ratchet_key.as_deref(),
            )
            .await?;
        Ok(result)
    }
}

/// Reference implementation of [traits::RatchetKeyStore].
#[derive(Clone)]
pub struct KeyChatRatchetKeyStore {
    pool: LitePool,
}

impl KeyChatRatchetKeyStore {
    pub async fn get_ratchet_key_by_public(
        &self,
        ratchet_key: &str,
    ) -> Result<Option<SignalRatchetKey>> {
        let sql = format!("select aliceRatchetKeyPublic, address, device, roomId, bobRatchetKeyPrivate, ratchetKeyHash from {} where aliceRatchetKeyPublic = ? order by id desc limit 1", self.pool.definition_ratchet_key());
        let result = sqlx::query(&sql)
            .bind(ratchet_key)
            .fetch_optional(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute get_ratchet_key_by_public error: {}", e).to_string(),
                )
            })?;
        if result.is_none() {
            return Ok(None);
        }
        let row = result.unwrap();
        let ratchet_key = SignalRatchetKey {
            alice_ratchet_key_public: row.get(0),
            address: row.get(1),
            device: row.get::<'_, i64, _>(2).to_string(),
            room_id: u32::try_from(row.get::<'_, i64, _>(3)).map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("get room_id from ratchet error: {}", e).to_string(),
                )
            })?,
            bob_ratchet_key_private: row.get(4),
            ratchet_key_hash: row.get(5),
        };

        Ok(Some(ratchet_key))
    }

    /// insert ratchetkey
    pub async fn insert_ratchet_key(&self, ratchet_key: SignalRatchetKey) -> Result<()> {
        let sql = format!("INSERT INTO {} (aliceRatchetKeyPublic, address, device, roomId, bobRatchetKeyPrivate, ratchetKeyHash) values (?, ?, ?, ?, ?, ?)", self.pool.definition_ratchet_key());
        sqlx::query(&sql)
            .bind(&ratchet_key.alice_ratchet_key_public)
            .bind(&ratchet_key.address)
            .bind(&ratchet_key.device)
            .bind(ratchet_key.room_id)
            .bind(&ratchet_key.bob_ratchet_key_private)
            .bind(&ratchet_key.ratchet_key_hash)
            .execute(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute insert_ratchet_key error: {}", e).to_string(),
                )
            })?;

        Ok(())
    }

    pub async fn delete_by_ratchet_key(&self, ratchet_key: &str) -> Result<()> {
        let sql = format!(
            "delete from {} where aliceRatchetKeyPublic = ?",
            self.pool.definition_ratchet_key()
        );
        let result = sqlx::query(&sql)
            .bind(ratchet_key)
            .execute(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute delete_by_ratchet_key error: {}", e).to_string(),
                )
            })?;
        let cnt = result.rows_affected();
        if cnt > 0 {
            info!(
                "delete {} old ratchet_key records for ({:?})",
                cnt, ratchet_key
            );
        }

        Ok(())
    }

    pub async fn delete_by_address_id(&self, id: u32, address: &str, room_id: u32) -> Result<()> {
        let sql = format!(
            "delete from {} where address = ? and roomId = ? and id <= ?",
            self.pool.definition_ratchet_key()
        );
        let result = sqlx::query(&sql)
            .bind(address)
            .bind(room_id)
            .bind(id)
            .execute(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute delete_by_address_id error: {}", e).to_string(),
                )
            })?;
        let cnt = result.rows_affected();
        if cnt > 0 {
            info!(
                "delete {} old ratchet_key records for {:?}, room_id: {}, and id <= {})",
                cnt, address, room_id, id
            );
        }
        Ok(())
    }

    pub async fn get_max_id_bak(&self, address: &str, room_id: u32) -> Result<Option<u32>> {
        let sql = format!(
            "select max(id) from {} where address = ? and roomId = ?",
            self.pool.definition_ratchet_key()
        );
        let result = sqlx::query(&sql)
            .bind(address)
            .bind(room_id)
            .fetch_optional(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute get_max_id error: {}", e).to_string(),
                )
            })?;
        if result.is_none() {
            return Ok(None);
        }
        let row = result.unwrap();
        let id = row.get(0);
        // let id = match id {
        //     Ok(id) => {
        //         let max_id:u32 = id;
        //         Some(max_id)
        //     },
        //     Err(_err) =>  None,
        // };
        Ok(id)
    }

    /// load_ratchet_key_bak
    pub async fn load_ratchet_key_bak(&self, their_ephemeral_public: String) -> Result<String> {
        let ratchet_key = self
            .get_ratchet_key_by_public(&their_ephemeral_public)
            .await?;
        let private = ratchet_key
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument("ratchet_key not found".to_string())
            })?
            .bob_ratchet_key_private;
        Ok(private)
    }

    /// store_ratchet_key_new
    pub async fn store_ratchet_key_bak(
        &mut self,
        address: &ProtocolAddress,
        room_id: u32,
        their_ephemeral_public: String,
        our_ephemeral_private: String,
    ) -> Result<()> {
        let max_id_option = self.get_max_id_bak(address.name(), room_id).await?;
        let max_id = match max_id_option {
            Some(id) => id,
            None => 0,
        };
        if max_id > 2 {
            self.delete_by_address_id(max_id - 2, address.name(), room_id)
                .await?;
        }
        self.insert_ratchet_key(SignalRatchetKey {
            alice_ratchet_key_public: their_ephemeral_public,
            room_id,
            address: address.name().to_owned(),
            device: address.device_id().to_string(),
            bob_ratchet_key_private: our_ephemeral_private,
            ratchet_key_hash: None,
        })
        .await?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl RatchetKeyStore for KeyChatRatchetKeyStore {
    /// use load_ratchet_key_bak instead
    async fn load_ratchet_key(&self, their_ephemeral_public: String) -> Result<String> {
        // let ratchet_key = futures::executor::block_on(async move {
        //     self.load_ratchet_key_bak(their_ephemeral_public).await
        // });
        // ratchet_key
        self.load_ratchet_key_bak(their_ephemeral_public).await
    }
    /// use store_ratchet_key_bak instead
    async fn store_ratchet_key(
        &mut self,
        address: &ProtocolAddress,
        room_id: u32,
        their_ephemeral_public: String,
        our_ephemeral_private: String,
    ) -> Result<()> {
        // let (mp, mc) = flume::bounded(0);

        // let address = address.clone();
        // let room_id = room_id.clone();
        // let mut self_clone = self.clone();
        // let _res = tokio::spawn(async move {
        //     let r = self_clone.store_ratchet_key_bak(
        //         &address,
        //         room_id,
        //         their_ephemeral_public,
        //         our_ephemeral_private,
        //     )
        //     .await;

        //     mp.send(r).expect("Send error");
        // });
        // mc.recv().unwrap().expect("Accept error");
        // Ok(())
        // //     self.store_ratchet_key_bak(
        // //         address,
        // //         room_id,
        // //         their_ephemeral_public,
        // //         our_ephemeral_private,
        // //     )
        // //     .await
        // // })
        self.store_ratchet_key_bak(
            address,
            room_id,
            their_ephemeral_public,
            our_ephemeral_private,
        )
        .await?;
        Ok(())
    }
    /// delete_old_ratchet_key
    async fn delete_old_ratchet_key(&self, id: u32, address: String, room_id: u32) -> Result<()> {
        self.delete_by_address_id(id, &address, room_id).await?;
        Ok(())
    }
    /// get_max_id
    async fn get_max_id(&self, address: &ProtocolAddress, room_id: u32) -> Result<Option<u32>> {
        let max_id = self.get_max_id_bak(address.name(), room_id).await?;
        Ok(max_id)
    }
    /// contains_ratchet_key, do not use
    async fn contains_ratchet_key(&self, _their_ephemeral_public: String) -> Result<Option<bool>> {
        Ok(Some(true))
    }
    /// remove_ratchet_key
    async fn remove_ratchet_key(&self, their_ephemeral_public: String) -> Result<()> {
        self.delete_by_ratchet_key(&their_ephemeral_public).await?;
        Ok(())
    }
}

/// Reference implementation of [traits::KyberPreKeyStore].
#[derive(Clone)]
pub struct KeyChatKyberPreKeyStore {
    kyber_pre_keys: HashMap<KyberPreKeyId, KyberPreKeyRecord>,
}

impl KeyChatKyberPreKeyStore {
    /// new
    pub fn new() -> Self {
        Self {
            kyber_pre_keys: HashMap::new(),
        }
    }

    /// Returns all registered Kyber pre-key ids
    pub async fn all_kyber_pre_key_ids(&self) -> impl Iterator<Item = &KyberPreKeyId> {
        self.kyber_pre_keys.keys()
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for KeyChatKyberPreKeyStore {
    async fn get_kyber_pre_key(&self, kyber_prekey_id: KyberPreKeyId) -> Result<KyberPreKeyRecord> {
        Ok(self
            .kyber_pre_keys
            .get(&kyber_prekey_id)
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?
            .clone())
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<()> {
        self.kyber_pre_keys
            .insert(kyber_prekey_id, record.to_owned());
        Ok(())
    }

    async fn mark_kyber_pre_key_used(&mut self, _kyber_prekey_id: KyberPreKeyId) -> Result<()> {
        Ok(())
    }
}

/// Reference implementation of [traits::SignedPreKeyStore].
#[derive(Clone)]
pub struct KeyChatSignedPreKeyStore {
    pool: LitePool,
}

impl KeyChatSignedPreKeyStore {
    async fn get_signed_pre_key(&self, key_id: SignedPreKeyId) -> Result<SignedPreKeyRecord> {
        let sql = format!(
            "select used, record from {} where keyId = ? order by id desc limit 1",
            self.pool.definition_signed_key()
        );
        let row = sqlx::query(&sql)
            .bind(key_id.to_string())
            .fetch_optional(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute get_signed_pre_key error: {}", e).to_string(),
                )
            })?
            .ok_or_else(|| {
                SignalProtocolError::InvalidArgument("signed_pre_key not found".to_string())
            })?;
        let record: String = row.get(1);
        let record_vec: Vec<u8> = decode_str_to_bytes(&record).map_err(|e| {
            SignalProtocolError::InvalidArgument(format!("record deserialize error: {}", e))
        })?;
        let signed_record = SignedPreKeyRecord::deserialize(&record_vec)?;
        Ok(signed_record)
    }

    async fn save_signed_pre_key(
        &mut self,
        key_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        let sql = format!(
            "INSERT INTO {} (keyId, record) values (?, ?)",
            self.pool.definition_signed_key()
        );
        let record_to_str = hex::encode(record.serialize().map_err(|_| {
            SignalProtocolError::InvalidArgument("record serialize error".to_string())
        })?);
        sqlx::query(&sql)
            .bind(&key_id.to_string())
            .bind(&record_to_str)
            .execute(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute save_signed_pre_key error: {}", e).to_string(),
                )
            })?;
        Ok(())
    }

    pub async fn remove_signed_pre_key(&mut self, key_id: SignedPreKeyId) -> Result<()> {
        // let sql = format!(
        //     "delete from {} where keyId = ?",
        //     self.pool.definition_signed_key()
        // );
        let sql = format!(
            "update {} set used = true where keyId = ?",
            self.pool.definition_signed_key()
        );
        let result = sqlx::query(&sql)
            .bind(key_id.to_string())
            .execute(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute remove_signed_pre_key error: {}", e).to_string(),
                )
            })?;

        let cnt = result.rows_affected();
        if cnt > 0 {
            info!("delete {} old signed_pre_key records", cnt);
        }
        Ok(())
    }

    /// Returns all registered signed pre-key ids
    pub async fn all_signed_pre_key_ids(&self) -> Result<Vec<SignedPreKeyId>> {
        let sql = format!("select keyId from {}", self.pool.definition_signed_key());

        // let key_ids = futures::executor::block_on(async move {
        //     let mut key_ids = Vec::new();
        //     let mut iter = sqlx::query(&sql).fetch(&self.pool.db);
        //     while let Some(it) = iter.next().await {
        //         let it = it.ok_or_else(|e| SignalProtocolError::InvalidArgument(format!("all_signed_pre_key_ids fetch error: {}", e)))?;
        //         let id: u32 = it.get(0);
        //         key_ids.push(SignedPreKeyId::from(id));
        //     }
        //     key_ids
        // });
        let mut key_ids = Vec::new();
        let mut iter = sqlx::query(&sql).fetch(&self.pool.db);
        while let Some(it) = iter.next().await {
            let it = it.map_err(|e| SignalProtocolError::InvalidArgument(format!("all_signed_pre_key_ids fetch error: {}", e)))?;
            let id: u32 = it.get(0);
            key_ids.push(SignedPreKeyId::from(id));
        }
        Ok(key_ids)
    }

    pub async fn generate_signed_key(
        &mut self,
        signal_identity_private_key: PrivateKey,
    ) -> Result<(u32, PublicKey, Vec<u8>, Vec<u8>)> {
        // first del over 24*3h data
        self.delete_old_signed_pre_key().await?;
        let bob_sign_id = random::<u32>();
        let mut csprng = OsRng;
        let pair = KeyPair::generate(&mut csprng);
        let bob_signed_signature = signal_identity_private_key
            .calculate_signature(&pair.public_key.serialize(), &mut OsRng)?;
        // get current Unix timestamp
        let unix_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let record = SignedPreKeyRecord::new(
            bob_sign_id.into(),
            unix_timestamp,
            &pair,
            &bob_signed_signature,
        );
        self.save_signed_pre_key(bob_sign_id.into(), &record)
            .await?;
        Ok((
            bob_sign_id,
            pair.public_key,
            bob_signed_signature.to_vec(),
            record.serialize()?,
        ))
    }

    /// del over 24*3h signed_key
    pub async fn delete_old_signed_pre_key(&mut self) -> Result<()> {
        let sql = format!(
            "delete from {} where createdAt <= datetime('now', '-1 day')",
            self.pool.definition_signed_key()
        );
        let result = sqlx::query(&sql)
            .execute(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute delete_old_signed_pre_key error: {}", e).to_string(),
                )
            })?;

        let cnt = result.rows_affected();
        if cnt > 0 {
            info!("delete {} old delete_old_signed_pre_key records", cnt);
        }
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for KeyChatSignedPreKeyStore {
    async fn get_signed_pre_key(&self, key_id: SignedPreKeyId) -> Result<SignedPreKeyRecord> {
        self.get_signed_pre_key(key_id).await
    }

    async fn save_signed_pre_key(
        &mut self,
        key_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        self.save_signed_pre_key(key_id, record).await
    }
}

/// Reference implementation of [traits::PreKeyStore].
#[derive(Clone)]
pub struct KeyChatPreKeyStore {
    pool: LitePool,
}

impl KeyChatPreKeyStore {
    async fn get_pre_key(&self, key_id: PreKeyId) -> Result<PreKeyRecord> {
        let sql = format!("select used, record, strftime('%s', createdAt) as int_time from {} where keyId = ? order by id desc limit 1", self.pool.definition_pre_key());
        let row = sqlx::query(&sql)
            .bind(key_id.to_string())
            .fetch_optional(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute get_pre_key error: {}", e).to_string(),
                )
            })?
            .ok_or_else(|| SignalProtocolError::InvalidArgument("pre_key not found".to_string()))?;
        let record: String = row.get(1);
        let record_vec: Vec<u8> = decode_str_to_bytes(&record).map_err(|e| {
            SignalProtocolError::InvalidArgument(format!("record deserialize error: {}", e))
        })?;
        let prekey_record = PreKeyRecord::deserialize(&record_vec)?;
        Ok(prekey_record)
    }

    async fn save_pre_key(&mut self, key_id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        let sql = format!(
            "INSERT INTO {} (keyId, record) values (?, ?)",
            self.pool.definition_pre_key()
        );
        let record_to_str = hex::encode(record.serialize().map_err(|_| {
            SignalProtocolError::InvalidArgument("record serialize error".to_string())
        })?);
        sqlx::query(&sql)
            .bind(&key_id.to_string())
            .bind(&record_to_str)
            .execute(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute save_pre_key error: {}", e).to_string(),
                )
            })?;
        Ok(())
    }

    /// remove pre_key
    async fn remove_pre_key(&mut self, key_id: PreKeyId) -> Result<()> {
        // let sql = format!(
        //     "delete from {} where keyId = ?",
        //     self.pool.definition_pre_key()
        // );
        let sql = format!(
            "update {} set used = true where keyId = ?",
            self.pool.definition_pre_key()
        );
        let result = sqlx::query(&sql)
            .bind(key_id.to_string())
            .execute(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute remove_pre_key error: {}", e).to_string(),
                )
            })?;
        let cnt = result.rows_affected();
        if cnt > 0 {
            info!("update {} old pre_key records used", cnt);
        }
        Ok(())
    }

    /// Returns all registered signed pre-key ids
    pub async fn all_pre_key_ids(&self) -> Result<Vec<PreKeyId>> {
        let sql = format!("select keyId from {}", self.pool.definition_pre_key());

        // let key_ids = futures::executor::block_on(async move {
            // let mut key_ids = Vec::new();
            // let mut iter = sqlx::query(&sql).fetch(&self.pool.db);
            // while let Some(it) = iter.next().await {
            //     let it = it.unwrap();
            //     let id: u32 = it.get(0);
            //     key_ids.push(PreKeyId::from(id));
            // }
            // key_ids
        // });
        let mut key_ids = Vec::new();
        let mut iter = sqlx::query(&sql).fetch(&self.pool.db);
        while let Some(it) = iter.next().await {
            let it = it.map_err(|e| SignalProtocolError::InvalidArgument(format!("all_pre_key_ids fetch error: {}", e)))?;
            let id: u32 = it.get(0);
            key_ids.push(PreKeyId::from(id));
        };
        Ok(key_ids)
    }

    /// del over 24*3h pre_key
    pub async fn delete_old_pre_key(&mut self) -> Result<()> {
        let sql = format!(
            "delete from {} where createdAt <= datetime('now', '-1 day')",
            self.pool.definition_pre_key()
        );
        let result = sqlx::query(&sql)
            .execute(&self.pool.db)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidArgument(
                    format_err!("execute delete_old_pre_key error: {}", e).to_string(),
                )
            })?;
        let cnt = result.rows_affected();
        if cnt > 0 {
            info!("delete {} old pre_key records", cnt);
        }
        Ok(())
    }

    pub async fn generate_pre_key(&mut self) -> Result<(u32, PublicKey, Vec<u8>)> {
        // first del over 24*3 data
        self.delete_old_pre_key().await?;
        let prekey_id = random::<u32>();
        let mut csprng = OsRng;
        let pair = KeyPair::generate(&mut csprng);
        let record = PreKeyRecord::new(prekey_id.into(), &pair);
        self.save_pre_key(prekey_id.into(), &record).await?;
        Ok((prekey_id, pair.public_key, record.serialize()?))
    }
}

#[async_trait(?Send)]
impl PreKeyStore for KeyChatPreKeyStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord> {
        self.get_pre_key(prekey_id).await
    }

    /// Set the entry for `prekey_id` to the value of `record`.
    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        // This overwrites old values, which matches Java behavior, but is it correct?
        self.save_pre_key(prekey_id, record).await
    }

    /// Remove the entry for `prekey_id`.
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<()> {
        // If id does not exist this silently does nothing
        self.remove_pre_key(prekey_id).await
    }
}

/// Reference implementation of [traits::ProtocolStore].
pub struct KeyChatSignalProtocolStore {
    /// KeyChatSessionStore
    pub session_store: KeyChatSessionStore,
    /// KeyChatIdentityKeyStore
    pub identity_store: KeyChatIdentityKeyStore,
    /// KeyChatRatchetKeyStore
    pub ratchet_key_store: KeyChatRatchetKeyStore,
    /// KeyChatKyberPreKeyStore
    pub kyber_pre_key_store: KeyChatKyberPreKeyStore,
    /// KeyChatSignedPreKeyStore
    pub signed_pre_key_store: KeyChatSignedPreKeyStore,
    /// KeyChatPreKeyStore
    pub pre_key_store: KeyChatPreKeyStore,
}

impl KeyChatSignalProtocolStore {
    /// Create an object with the minimal implementation of [traits::ProtocolStore], representing
    /// the given identity `key_pair` along with the separate randomly chosen `registration_id`.
    pub fn new(pool: LitePool, key_pair: IdentityKeyPair, registration_id: u32) -> Result<Self> {
        Ok(Self {
            session_store: KeyChatSessionStore { pool: pool.clone() },
            identity_store: KeyChatIdentityKeyStore {
                pool: pool.clone(),
                key_pair,
                registration_id,
            },
            ratchet_key_store: KeyChatRatchetKeyStore { pool: pool.clone() },
            kyber_pre_key_store: KeyChatKyberPreKeyStore::new(),
            signed_pre_key_store: KeyChatSignedPreKeyStore { pool: pool.clone() },
            pre_key_store: KeyChatPreKeyStore { pool: pool.clone() },
        })
    }

    pub fn get_identity_store(&self) -> Result<KeyChatIdentityKeyStore> {
        Ok(self.identity_store.clone())
    }
    /// Returns all registered pre-key ids
    pub async fn all_pre_key_ids(&self) -> Result<Vec<PreKeyId>> {
        self.pre_key_store.all_pre_key_ids().await
    }

    /// Returns all registered signed pre-key ids
    pub async fn all_signed_pre_key_ids(&self) -> Result<Vec<SignedPreKeyId>> {
        self.signed_pre_key_store.all_signed_pre_key_ids().await
    }

    /// Returns all registered Kyber pre-key ids
    pub async fn all_kyber_pre_key_ids(&self) -> impl Iterator<Item = &KyberPreKeyId> {
        self.kyber_pre_key_store.all_kyber_pre_key_ids().await
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for KeyChatSignalProtocolStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        self.identity_store.get_identity_key_pair().await
    }

    async fn get_local_registration_id(&self) -> Result<u32> {
        self.identity_store.get_local_registration_id().await
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool> {
        self.identity_store.save_identity(address, identity).await
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool> {
        self.identity_store
            .is_trusted_identity(address, identity, direction)
            .await
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        self.identity_store.get_identity(address).await
    }
}

#[async_trait(?Send)]
impl SessionStore for KeyChatSignalProtocolStore {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        self.session_store.load_session(address).await
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        my_receiver_address: Option<String>,
        to_receiver_address: Option<String>,
        sender_ratchet_key: Option<String>,
    ) -> Result<(u32, Option<Vec<String>>)> {
        self.session_store
            .store_session(
                address,
                record,
                my_receiver_address,
                to_receiver_address,
                sender_ratchet_key,
            )
            .await
    }
}

#[async_trait(?Send)]
impl RatchetKeyStore for KeyChatSignalProtocolStore {
    async fn load_ratchet_key(&self, their_ephemeral_public: String) -> Result<String> {
        self.ratchet_key_store
            .load_ratchet_key(their_ephemeral_public)
            .await
    }

    async fn store_ratchet_key(
        &mut self,
        address: &ProtocolAddress,
        room_id: u32,
        their_ephemeral_public: String,
        our_ephemeral_private: String,
    ) -> Result<()> {
        self.ratchet_key_store
            .store_ratchet_key(
                address,
                room_id,
                their_ephemeral_public,
                our_ephemeral_private,
            )
            .await
    }

    async fn delete_old_ratchet_key(&self, id: u32, address: String, room_id: u32) -> Result<()> {
        self.ratchet_key_store
            .delete_old_ratchet_key(id, address, room_id)
            .await
    }

    async fn get_max_id(&self, address: &ProtocolAddress, room_id: u32) -> Result<Option<u32>> {
        self.ratchet_key_store.get_max_id(address, room_id).await
    }

    async fn contains_ratchet_key(&self, their_ephemeral_public: String) -> Result<Option<bool>> {
        self.ratchet_key_store
            .contains_ratchet_key(their_ephemeral_public)
            .await
    }

    async fn remove_ratchet_key(&self, their_ephemeral_public: String) -> Result<()> {
        self.ratchet_key_store
            .remove_ratchet_key(their_ephemeral_public)
            .await
    }
}

#[async_trait(?Send)]
impl PreKeyStore for KeyChatSignalProtocolStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord> {
        self.pre_key_store.get_pre_key(prekey_id).await
    }

    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<()> {
        self.pre_key_store.save_pre_key(prekey_id, record).await
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<()> {
        self.pre_key_store.remove_pre_key(prekey_id).await
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for KeyChatSignalProtocolStore {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> Result<SignedPreKeyRecord> {
        self.signed_pre_key_store.get_signed_pre_key(id).await
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<()> {
        self.signed_pre_key_store
            .save_signed_pre_key(id, record)
            .await
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for KeyChatSignalProtocolStore {
    async fn get_kyber_pre_key(&self, kyber_prekey_id: KyberPreKeyId) -> Result<KyberPreKeyRecord> {
        self.kyber_pre_key_store
            .get_kyber_pre_key(kyber_prekey_id)
            .await
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<()> {
        self.kyber_pre_key_store
            .save_kyber_pre_key(kyber_prekey_id, record)
            .await
    }

    async fn mark_kyber_pre_key_used(&mut self, kyber_prekey_id: KyberPreKeyId) -> Result<()> {
        self.kyber_pre_key_store
            .mark_kyber_pre_key_used(kyber_prekey_id)
            .await
    }
}

impl ProtocolStore for KeyChatSignalProtocolStore {}

pub fn decode_str_to_bytes(str: &str) -> anyhow::Result<Vec<u8>> {
    let val;
    if str.starts_with('[') {
        // old format
        val = serde_json::from_str(str)?;
    } else {
        val = hex::decode(str)?;
    }
    Ok(val)
}
