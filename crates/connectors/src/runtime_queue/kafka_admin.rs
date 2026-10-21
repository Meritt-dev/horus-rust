//! Minimal read-only Kafka admin client — the slice of kafkajs `admin()` that
//! `KafkaQueueProvider` uses: `fetchTopicOffsets` (Metadata + ListOffsets latest) and
//! `fetchOffsets` (FindCoordinator + OffsetFetch). Wire codecs come from `kafka-protocol`;
//! transport (TCP / TLS, ApiVersions negotiation, SASL PLAIN / SCRAM) is here.
//!
//! Never produces, consumes, commits offsets or creates topics (`allowAutoTopicCreation: false`).
//! Error texts follow kafkajs (`Connection error: …`, `Connection timeout`, broker error
//! messages) because they become the provider's health `detail`.

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use bytes::BytesMut;
use hmac::{Hmac, Mac};
use horus_core::{KafkaConfig, KafkaMechanism};
use kafka_protocol::messages::api_versions_request::ApiVersionsRequest;
use kafka_protocol::messages::find_coordinator_request::FindCoordinatorRequest;
use kafka_protocol::messages::list_offsets_request::{ListOffsetsPartition, ListOffsetsRequest, ListOffsetsTopic};
use kafka_protocol::messages::metadata_request::{MetadataRequest, MetadataRequestTopic};
use kafka_protocol::messages::offset_fetch_request::{OffsetFetchRequest, OffsetFetchRequestTopic};
use kafka_protocol::messages::sasl_authenticate_request::SaslAuthenticateRequest;
use kafka_protocol::messages::sasl_handshake_request::SaslHandshakeRequest;
use kafka_protocol::messages::{ApiKey, BrokerId, GroupId, RequestHeader, ResponseHeader, TopicName};
use kafka_protocol::protocol::{Decodable, Encodable, Message, Request, StrBytes};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// kafkajs options in the TS provider: `connectionTimeout: 5000`, `requestTimeout: 8000`.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const CLIENT_ID: &str = "horus-readonly";
/// kafkajs `ListOffsets` default (`ISOLATION_LEVEL.READ_COMMITTED`).
const READ_COMMITTED: i8 = 1;
/// `LATEST_OFFSET` timestamp (`fromBeginning: false`).
const LATEST: i64 = -1;

/// Highest version we encode per API — below the versions whose request shape changes
/// (topic ids / batched groups), so one struct layout covers every broker we talk to.
fn version_cap(key: ApiKey) -> i16 {
    match key {
        ApiKey::Metadata => 9,
        ApiKey::ListOffsets => 7,
        ApiKey::FindCoordinator => 3,
        ApiKey::OffsetFetch => 7,
        ApiKey::SaslHandshake => 1,
        ApiKey::SaslAuthenticate => 2,
        _ => 0,
    }
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Node's socket error wording (`connect ECONNREFUSED 127.0.0.1:9092`) for the common cases,
/// prefixed like kafkajs `KafkaJSConnectionError`.
fn connection_error(e: &std::io::Error, addr: &str) -> anyhow::Error {
    match crate::jsutil::node_connect_error(e, addr) {
        Some(msg) => anyhow!("Connection error: {msg}"),
        None => anyhow!("Connection error: {e}"),
    }
}

/// A broker error code as kafkajs reports it (its own message table, `kafkajs_error_message`).
fn broker_error(code: i16) -> Option<anyhow::Error> {
    if code == 0 {
        return None;
    }
    Some(match kafkajs_error_message(code) {
        Some(msg) => anyhow!("{msg}"),
        None => anyhow!("Unknown error code {code}"),
    })
}

struct Connection {
    stream: Box<dyn Stream>,
    correlation_id: i32,
    /// Broker-supported version ranges from ApiVersions.
    versions: HashMap<i16, (i16, i16)>,
}

impl Connection {
    async fn open(host: &str, port: i32, config: &KafkaConfig) -> Result<Connection> {
        let addr = format!("{host}:{port}");
        let connect = async {
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(addr.as_str())
                .await
                .map_err(|_| anyhow!("Connection error: getaddrinfo ENOTFOUND {host}"))?
                .collect();
            let mut last: Option<anyhow::Error> = None;
            for a in &addrs {
                match TcpStream::connect(a).await {
                    Ok(tcp) => {
                        tcp.set_nodelay(true).ok();
                        return Ok(tcp);
                    }
                    Err(e) => last = Some(connection_error(&e, &a.to_string())),
                }
            }
            Err(last.unwrap_or_else(|| anyhow!("Connection error: getaddrinfo ENOTFOUND {host}")))
        };
        let tcp = tokio::time::timeout(CONNECTION_TIMEOUT, connect).await.map_err(|_| anyhow!("Connection timeout"))??;
        let stream: Box<dyn Stream> = if config.ssl {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| anyhow!("Connection error: {e}"))?;
            let handshake = tokio_rustls::TlsConnector::from(Arc::new(tls)).connect(name, tcp);
            let s = tokio::time::timeout(CONNECTION_TIMEOUT, handshake)
                .await
                .map_err(|_| anyhow!("Connection timeout"))?
                .map_err(|e| match e.kind() {
                    // Node's text for a peer that hangs up mid-handshake (e.g. TLS against a plaintext port).
                    std::io::ErrorKind::UnexpectedEof => {
                        anyhow!("Connection error: Client network socket disconnected before secure TLS connection was established")
                    }
                    _ => anyhow!("Connection error: {e}"),
                })?;
            Box::new(s)
        } else {
            Box::new(tcp)
        };
        let mut conn = Connection { stream, correlation_id: 0, versions: HashMap::new() };
        // ApiVersions v0: understood by every broker generation, including 4.x.
        let res = conn.send_raw(ApiVersionsRequest::default(), ApiKey::ApiVersions, 0).await?;
        if let Some(e) = broker_error(res.error_code) {
            return Err(e);
        }
        conn.versions = res.api_keys.iter().map(|k| (k.api_key, (k.min_version, k.max_version))).collect();
        if let (Some(user), Some(pass)) = (config.username.as_deref(), config.password.as_deref()) {
            if !user.is_empty() && !pass.is_empty() {
                conn.authenticate(config.mechanism, user, pass).await?;
            }
        }
        Ok(conn)
    }

    /// Highest mutually supported version of `key`, bounded by what we encode.
    fn version<R: Message>(&self, key: ApiKey) -> Result<i16> {
        let (bmin, bmax) = self
            .versions
            .get(&(key as i16))
            .copied()
            .ok_or_else(|| anyhow!("The broker does not support the requested protocol version"))?;
        let lo = bmin.max(R::VERSIONS.min);
        let hi = bmax.min(R::VERSIONS.max).min(version_cap(key));
        if lo > hi {
            bail!("The broker does not support the requested protocol version");
        }
        Ok(hi)
    }

    async fn send<R: Request>(&mut self, req: R, key: ApiKey) -> Result<R::Response> {
        let version = self.version::<R>(key)?;
        self.send_raw(req, key, version).await
    }

    async fn send_raw<R: Request>(&mut self, req: R, key: ApiKey, version: i16) -> Result<R::Response> {
        self.correlation_id += 1;
        let correlation_id = self.correlation_id;
        let header = RequestHeader::default()
            .with_request_api_key(key as i16)
            .with_request_api_version(version)
            .with_correlation_id(correlation_id)
            .with_client_id(Some(StrBytes::from_static_str(CLIENT_ID)));
        let mut body = BytesMut::new();
        header.encode(&mut body, key.request_header_version(version))?;
        req.encode(&mut body, version)?;
        let mut frame = BytesMut::with_capacity(body.len() + 4);
        frame.extend_from_slice(&(body.len() as i32).to_be_bytes());
        frame.extend_from_slice(&body);

        let exchange = async {
            self.stream.write_all(&frame).await?;
            self.stream.flush().await?;
            let size = self.stream.read_i32().await?;
            if size < 0 {
                bail!("Invalid response size {size}");
            }
            let mut buf = vec![0u8; size as usize];
            self.stream.read_exact(&mut buf).await?;
            Ok::<Vec<u8>, anyhow::Error>(buf)
        };
        let raw = match tokio::time::timeout(REQUEST_TIMEOUT, exchange).await {
            Err(_) => bail!("Request {key:?}(key: {}, version: {version}) timed out", key as i16),
            Ok(Err(e)) => match e.downcast_ref::<std::io::Error>() {
                // kafkajs `KafkaJSConnectionClosedError` for a broker hang-up on an established
                // connection (its "Connection closed by the server" is only the legacy raw-SASL path).
                Some(io) if io.kind() == std::io::ErrorKind::UnexpectedEof => bail!("Closed connection"),
                _ => return Err(e),
            },
            Ok(Ok(raw)) => raw,
        };
        let mut buf = bytes::Bytes::from(raw);
        let res_header = ResponseHeader::decode(&mut buf, key.response_header_version(version))?;
        if res_header.correlation_id != correlation_id {
            bail!("Correlation id mismatch: expected {correlation_id}, got {}", res_header.correlation_id);
        }
        Ok(R::Response::decode(&mut buf, version)?)
    }

    async fn sasl_round(&mut self, auth_bytes: Vec<u8>) -> Result<Vec<u8>> {
        let req = SaslAuthenticateRequest::default().with_auth_bytes(auth_bytes.into());
        let res = self.send(req, ApiKey::SaslAuthenticate).await?;
        if res.error_code != 0 {
            let msg = res.error_message.map(|m| m.to_string()).filter(|m| !m.is_empty());
            let fallback = broker_error(res.error_code).map(|e| e.to_string()).unwrap_or_default();
            bail!("{}", msg.unwrap_or(fallback));
        }
        Ok(res.auth_bytes.to_vec())
    }

    async fn authenticate(&mut self, mechanism: KafkaMechanism, user: &str, pass: &str) -> Result<()> {
        let name = match mechanism {
            KafkaMechanism::Plain => "PLAIN",
            KafkaMechanism::ScramSha256 => "SCRAM-SHA-256",
            KafkaMechanism::ScramSha512 => "SCRAM-SHA-512",
        };
        let hs = self.send(SaslHandshakeRequest::default().with_mechanism(StrBytes::from_static_str(name)), ApiKey::SaslHandshake).await?;
        if hs.error_code != 0 {
            let enabled: Vec<String> = hs.mechanisms.iter().map(|m| m.to_string()).collect();
            bail!("SASL {name} mechanism is not supported by the server (enabled: {})", enabled.join(", "));
        }
        let result = match mechanism {
            KafkaMechanism::Plain => self.sasl_round(format!("\0{user}\0{pass}").into_bytes()).await.map(|_| ()),
            KafkaMechanism::ScramSha256 => self.scram(ScramHash::Sha256, user, pass).await,
            KafkaMechanism::ScramSha512 => self.scram(ScramHash::Sha512, user, pass).await,
        };
        // kafkajs prefixes: `SASL PLAIN …`, `SASL SCRAM SHA256 …`, `SASL SCRAM SHA512 …`.
        let label = match mechanism {
            KafkaMechanism::Plain => "PLAIN",
            KafkaMechanism::ScramSha256 => "SCRAM SHA256",
            KafkaMechanism::ScramSha512 => "SCRAM SHA512",
        };
        result.map_err(|e| anyhow!("SASL {label} authentication failed: {e}"))
    }

    /// RFC 5802 SCRAM client exchange over SaslAuthenticate.
    async fn scram(&mut self, alg: ScramHash, user: &str, pass: &str) -> Result<()> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let nonce: String = {
            use rand::RngCore;
            let mut raw = [0u8; 24];
            rand::thread_rng().fill_bytes(&mut raw);
            b64.encode(raw)
        };
        let saslname = user.replace('=', "=3D").replace(',', "=2C");
        let client_first_bare = format!("n={saslname},r={nonce}");
        let server_first = String::from_utf8(self.sasl_round(format!("n,,{client_first_bare}").into_bytes()).await?)?;
        let attr = |msg: &str, k: char| msg.split(',').find_map(|p| p.strip_prefix(&format!("{k}=")).map(str::to_string));
        if let Some(e) = attr(&server_first, 'e') {
            bail!("{e}");
        }
        let server_nonce = attr(&server_first, 'r').ok_or_else(|| anyhow!("Invalid server nonce"))?;
        if !server_nonce.starts_with(&nonce) {
            bail!("Server nonce does not start with client nonce");
        }
        let salt = b64.decode(attr(&server_first, 's').ok_or_else(|| anyhow!("Invalid salt"))?)?;
        let iterations: u32 = attr(&server_first, 'i').ok_or_else(|| anyhow!("Invalid iterations"))?.parse()?;

        let salted = alg.salted_password(pass, &salt, iterations);
        let hmac = |key: &[u8], data: &[u8]| alg.hmac(key, data);
        let client_key = hmac(&salted, b"Client Key");
        let stored_key = alg.hash(&client_key);
        let without_proof = format!("c=biws,r={server_nonce}");
        let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
        let signature = hmac(&stored_key, auth_message.as_bytes());
        let proof: Vec<u8> = client_key.iter().zip(&signature).map(|(a, b)| a ^ b).collect();
        let server_final =
            String::from_utf8(self.sasl_round(format!("{without_proof},p={}", b64.encode(proof)).into_bytes()).await?)?;
        if let Some(e) = attr(&server_final, 'e') {
            bail!("{e}");
        }
        let server_key = hmac(&salted, b"Server Key");
        let expected = b64.encode(hmac(&server_key, auth_message.as_bytes()));
        if attr(&server_final, 'v').as_deref() != Some(expected.as_str()) {
            bail!("Invalid server signature in server final message");
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ScramHash {
    Sha256,
    Sha512,
}

impl ScramHash {
    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            ScramHash::Sha256 => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            ScramHash::Sha512 => {
                let mut m = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }
    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            ScramHash::Sha256 => Sha256::digest(data).to_vec(),
            ScramHash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
    fn salted_password(self, pass: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
        match self {
            ScramHash::Sha256 => pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(pass.as_bytes(), salt, iterations).to_vec(),
            ScramHash::Sha512 => pbkdf2::pbkdf2_hmac_array::<Sha512, 64>(pass.as_bytes(), salt, iterations).to_vec(),
        }
    }
}

/// One partition's leader from Metadata, in broker response order.
struct PartitionMeta {
    partition: i32,
    leader: i32,
}

/// `fetchTopicOffsets` result entry (`high` = latest offset as a decimal string).
pub(crate) struct TopicOffset {
    pub partition: i32,
    pub high: String,
}

pub(crate) struct KafkaAdmin {
    config: KafkaConfig,
    seed: Connection,
    brokers: HashMap<i32, (String, i32)>,
    by_node: HashMap<i32, Connection>,
}

impl KafkaAdmin {
    /// `admin.connect()`: reach a seed broker (each configured broker in turn, one retry
    /// round like `retry: { retries: 1 }`) and negotiate versions / SASL.
    pub(crate) async fn connect(config: &KafkaConfig) -> Result<KafkaAdmin> {
        let mut last: Option<anyhow::Error> = None;
        for _attempt in 0..2 {
            for b in &config.brokers {
                let Some((host, port)) = b.rsplit_once(':') else { continue };
                let port: i32 = port.parse().unwrap_or(9092);
                match Connection::open(host, port, config).await {
                    Ok(seed) => {
                        return Ok(KafkaAdmin { config: config.clone(), seed, brokers: HashMap::new(), by_node: HashMap::new() })
                    }
                    Err(e) => last = Some(e),
                }
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("Failed to connect to seed broker")))
    }

    async fn topic_metadata(&mut self, topic: &str) -> Result<Vec<PartitionMeta>> {
        let req = MetadataRequest::default()
            .with_topics(Some(vec![MetadataRequestTopic::default().with_name(Some(TopicName(StrBytes::from_string(topic.to_string()))))]))
            .with_allow_auto_topic_creation(false);
        let res = self.seed.send(req, ApiKey::Metadata).await?;
        for b in &res.brokers {
            self.brokers.insert(b.node_id.0, (b.host.to_string(), b.port));
        }
        let t = res
            .topics
            .iter()
            .find(|t| t.name.as_ref().map(|n| n.0.as_str()) == Some(topic))
            .ok_or_else(|| anyhow!("This server does not host this topic-partition"))?;
        if let Some(e) = broker_error(t.error_code) {
            return Err(e);
        }
        Ok(t.partitions.iter().map(|p| PartitionMeta { partition: p.partition_index, leader: p.leader_id.0 }).collect())
    }

    /// Connection to a broker by node id (the seed's own node is reopened once; cheap and simple).
    async fn node(&mut self, node_id: i32) -> Result<&mut Connection> {
        if !self.by_node.contains_key(&node_id) {
            let (host, port) = self
                .brokers
                .get(&node_id)
                .cloned()
                .ok_or_else(|| anyhow!("Broker {node_id} not found in the cached metadata"))?;
            let conn = Connection::open(&host, port, &self.config).await?;
            self.by_node.insert(node_id, conn);
        }
        Ok(self.by_node.get_mut(&node_id).expect("inserted above"))
    }

    /// kafkajs `admin.fetchTopicOffsets(topic)` (high side only). Partitions are grouped by
    /// leader node id ascending (JS integer-key order of `partitionsPerBroker`), each group in
    /// the broker's response order — the order the TS evidence lists them in. One retry on
    /// `UNKNOWN_TOPIC_OR_PARTITION`, as kafkajs refreshes metadata and retries.
    pub(crate) async fn fetch_topic_offsets(&mut self, topic: &str) -> Result<Vec<TopicOffset>> {
        match self.fetch_topic_offsets_once(topic).await {
            Err(e) if e.to_string() == "This server does not host this topic-partition" => self.fetch_topic_offsets_once(topic).await,
            other => other,
        }
    }

    async fn fetch_topic_offsets_once(&mut self, topic: &str) -> Result<Vec<TopicOffset>> {
        let meta = self.topic_metadata(topic).await?;
        let mut per_leader: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
        for p in &meta {
            per_leader.entry(p.leader).or_default().push(p.partition);
        }
        let mut out = Vec::new();
        for (leader, partitions) in per_leader {
            let req = ListOffsetsRequest::default()
                .with_replica_id(BrokerId(-1))
                .with_isolation_level(READ_COMMITTED)
                .with_topics(vec![ListOffsetsTopic::default()
                    .with_name(TopicName(StrBytes::from_string(topic.to_string())))
                    .with_partitions(
                        partitions
                            .iter()
                            .map(|p| ListOffsetsPartition::default().with_partition_index(*p).with_timestamp(LATEST).with_current_leader_epoch(-1))
                            .collect(),
                    )]);
            let res = self.node(leader).await?.send(req, ApiKey::ListOffsets).await?;
            for t in res.topics {
                for p in t.partitions {
                    if let Some(e) = broker_error(p.error_code) {
                        return Err(e);
                    }
                    out.push(TopicOffset { partition: p.partition_index, high: p.offset.to_string() });
                }
            }
        }
        Ok(out)
    }

    /// kafkajs `admin.fetchOffsets({ groupId, topics: [topic] })` → partition → committed offset
    /// string (`"-1"` when the group never committed that partition, exactly as kafkajs returns it).
    pub(crate) async fn fetch_offsets(&mut self, group_id: &str, topic: &str) -> Result<HashMap<i32, String>> {
        let coord = self
            .seed
            .send(FindCoordinatorRequest::default().with_key(StrBytes::from_string(group_id.to_string())).with_key_type(0), ApiKey::FindCoordinator)
            .await?;
        if let Some(e) = broker_error(coord.error_code) {
            return Err(e);
        }
        self.brokers.insert(coord.node_id.0, (coord.host.to_string(), coord.port));
        // `findTopicPartitions(...).sort()` — JS default sort is lexicographic.
        let mut partitions: Vec<i32> = self.topic_metadata(topic).await?.iter().map(|p| p.partition).collect();
        partitions.sort_by_key(|p| p.to_string());
        let req = OffsetFetchRequest::default()
            .with_group_id(GroupId(StrBytes::from_string(group_id.to_string())))
            .with_topics(Some(vec![OffsetFetchRequestTopic::default()
                .with_name(TopicName(StrBytes::from_string(topic.to_string())))
                .with_partition_indexes(partitions)]));
        let res = self.node(coord.node_id.0).await?.send(req, ApiKey::OffsetFetch).await?;
        if let Some(e) = broker_error(res.error_code) {
            return Err(e);
        }
        let mut out = HashMap::new();
        for t in res.topics.iter().filter(|t| t.name.0.as_str() == topic) {
            for p in &t.partitions {
                if let Some(e) = broker_error(p.error_code) {
                    return Err(e);
                }
                out.insert(p.partition_index, p.committed_offset.to_string());
            }
        }
        Ok(out)
    }
}

/// kafkajs 2.2.4 `protocol/error.js` messages (what the TS CLI prints for a broker error code).
/// Generated from that table; kafka-protocol only exposes the variant names.
fn kafkajs_error_message(code: i16) -> Option<&'static str> {
    Some(match code {
        -1 => "The server experienced an unexpected error when processing the request",
        1 => "The requested offset is not within the range of offsets maintained by the server",
        2 => "This message has failed its CRC checksum, exceeds the valid size, or is otherwise corrupt",
        3 => "This server does not host this topic-partition",
        4 => "The requested fetch size is invalid",
        5 => "There is no leader for this topic-partition as we are in the middle of a leadership election",
        6 => "This server is not the leader for that topic-partition",
        7 => "The request timed out",
        8 => "The broker is not available",
        9 => "The replica is not available for the requested topic-partition",
        10 => "The request included a message larger than the max message size the server will accept",
        11 => "The controller moved to another broker",
        12 => "The metadata field of the offset request was too large",
        13 => "The server disconnected before a response was received",
        14 => "The coordinator is loading and hence can't process requests for this group",
        15 => "The group coordinator is not available",
        16 => "This is not the correct coordinator for this group",
        17 => "The request attempted to perform an operation on an invalid topic",
        18 => "The request included message batch larger than the configured segment size on the server",
        19 => "Messages are rejected since there are fewer in-sync replicas than required",
        20 => "Messages are written to the log, but to fewer in-sync replicas than required",
        21 => "Produce request specified an invalid value for required acks",
        22 => "Specified group generation id is not valid",
        23 => "The group member's supported protocols are incompatible with those of existing members",
        24 => "The configured groupId is invalid",
        25 => "The coordinator is not aware of this member",
        26 => "The session timeout is not within the range allowed by the broker (as configured by group.min.session.timeout.ms and group.max.session.timeout.ms)",
        27 => "The group is rebalancing, so a rejoin is needed",
        28 => "The committing offset data size is not valid",
        29 => "Not authorized to access topics: [Topic authorization failed]",
        30 => "Not authorized to access group: Group authorization failed",
        31 => "Cluster authorization failed",
        32 => "The timestamp of the message is out of acceptable range",
        33 => "The broker does not support the requested SASL mechanism",
        34 => "Request is not valid given the current SASL state",
        35 => "The version of API is not supported",
        36 => "Topic with this name already exists",
        37 => "Number of partitions is invalid",
        38 => "Replication-factor is invalid",
        39 => "Replica assignment is invalid",
        40 => "Configuration is invalid",
        41 => "This is not the correct controller for this cluster",
        42 => "This most likely occurs because of a request being malformed by the client library or the message was sent to an incompatible broker. See the broker logs for more details",
        43 => "The message format version on the broker does not support the request",
        44 => "Request parameters do not satisfy the configured policy",
        45 => "The broker received an out of order sequence number",
        46 => "The broker received a duplicate sequence number",
        47 => "Producer attempted an operation with an old epoch. Either there is a newer producer with the same transactionalId, or the producer's transaction has been expired by the broker",
        48 => "The producer attempted a transactional operation in an invalid state",
        49 => "The producer attempted to use a producer id which is not currently assigned to its transactional id",
        50 => "The transaction timeout is larger than the maximum value allowed by the broker (as configured by max.transaction.timeout.ms)",
        51 => "The producer attempted to update a transaction while another concurrent operation on the same transaction was ongoing",
        52 => "Indicates that the transaction coordinator sending a WriteTxnMarker is no longer the current coordinator for a given producer",
        53 => "Transactional Id authorization failed",
        54 => "Security features are disabled",
        55 => "The broker did not attempt to execute this operation. This may happen for batched RPCs where some operations in the batch failed, causing the broker to respond without trying the rest",
        56 => "Disk error when trying to access log file on the disk",
        57 => "The user-specified log directory is not found in the broker config",
        58 => "SASL Authentication failed",
        59 => "This exception is raised by the broker if it could not locate the producer metadata associated with the producerId in question. This could happen if, for instance, the producer's records were deleted because their retention time had elapsed. Once the last records of the producerId are removed, the producer's metadata is removed from the broker, and future appends by the producer will return this exception",
        60 => "A partition reassignment is in progress",
        61 => "Delegation Token feature is not enabled",
        62 => "Delegation Token is not found on server",
        63 => "Specified Principal is not valid Owner/Renewer",
        64 => "Delegation Token requests are not allowed on PLAINTEXT/1-way SSL channels and on delegation token authenticated channels",
        65 => "Delegation Token authorization failed",
        66 => "Delegation Token is expired",
        67 => "Supplied principalType is not supported",
        68 => "The group is not empty",
        69 => "The group id was not found",
        70 => "The fetch session ID was not found",
        71 => "The fetch session epoch is invalid",
        72 => "There is no listener on the leader broker that matches the listener on which metadata request was processed",
        73 => "Topic deletion is disabled",
        74 => "The leader epoch in the request is older than the epoch on the broker",
        75 => "The leader epoch in the request is newer than the epoch on the broker",
        76 => "The requesting client does not support the compression type of given partition",
        77 => "Broker epoch has changed",
        78 => "The leader high watermark has not caught up from a recent leader election so the offsets cannot be guaranteed to be monotonically increasing",
        79 => "The group member needs to have a valid member id before actually entering a consumer group",
        80 => "The preferred leader was not available",
        81 => "The consumer group has reached its max size. It already has the configured maximum number of members",
        82 => "The broker rejected this static consumer since another consumer with the same group instance id has registered with a different member id",
        83 => "Eligible topic partition leaders are not available",
        84 => "Leader election not needed for topic partition",
        85 => "No partition reassignment is in progress",
        86 => "Deleting offsets of a topic is forbidden while the consumer group is actively subscribed to it",
        87 => "This record has failed the validation on broker and hence be rejected",
        88 => "There are unstable offsets that need to be cleared",
        _ => return None,
    })
}
