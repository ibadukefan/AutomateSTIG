use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::keys::{HashAlg, PrivateKey};
use russh::server::{self, Auth, Session};
use russh::{Channel, ChannelId, Disconnect};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use automatestig_core::checks::CheckPlatform;
use automatestig_core::remote::{
    CollectionCommand, CollectionPlan, CommandEvidence, CommandStatus, OutputPolicy,
};

use super::{collect_plan, SshAuth, SshConfig, SshHandler};

const MAX_OUTPUT: usize = 50 * 1024 * 1024;

#[derive(Clone, Copy)]
enum Behavior {
    Success,
    NonzeroWithStderr,
    MissingExitStatus,
    DisconnectAfterPartialOutput,
    InvalidUtf8,
    OversizedOutput,
    Stall,
}

#[derive(Clone)]
struct FaultServer {
    behavior: Behavior,
    accept_auth: bool,
}

impl server::Handler for FaultServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if self.accept_auth && user == "scanner" && password == "correct-password" {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        match self.behavior {
            Behavior::Success => {
                session.data(channel, b"collected-value\n".to_vec())?;
                session.exit_status_request(channel, 0)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
            Behavior::NonzeroWithStderr => {
                session.data(channel, b"partial-stdout\n".to_vec())?;
                session.extended_data(channel, 1, b"permission denied\n".to_vec())?;
                session.exit_status_request(channel, 17)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
            Behavior::MissingExitStatus => {
                session.data(channel, b"untrusted-output\n".to_vec())?;
                session.eof(channel)?;
                session.close(channel)?;
            }
            Behavior::DisconnectAfterPartialOutput => {
                session.data(channel, b"truncated".to_vec())?;
                session.disconnect(Disconnect::ConnectionLost, "injected disconnect", "")?;
            }
            Behavior::InvalidUtf8 => {
                session.data(channel, vec![0xff, 0xfe, 0xfd])?;
                session.exit_status_request(channel, 0)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
            Behavior::OversizedOutput => {
                session.data(channel, vec![b'x'; MAX_OUTPUT + 1])?;
                session.exit_status_request(channel, 0)?;
                session.eof(channel)?;
                session.close(channel)?;
            }
            Behavior::Stall => {}
        }
        Ok(())
    }
}

struct RunningServer {
    port: u16,
    key_id: String,
    task: JoinHandle<()>,
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_server(behavior: Behavior, accept_auth: bool) -> RunningServer {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let host_key =
        PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519).unwrap();
    let key_id = host_key
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();

    let mut config = server::Config {
        auth_rejection_time: Duration::from_millis(10),
        inactivity_timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    };
    config.keys.push(host_key);
    let config = Arc::new(config);
    let handler = FaultServer {
        behavior,
        accept_auth,
    };
    let task = tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let _ = server::run_stream(config, stream, handler).await;
    });

    RunningServer { port, key_id, task }
}

fn trust_server(home: &Path, server: &RunningServer) {
    let trust_dir = home.join(".automatestig");
    std::fs::create_dir_all(&trust_dir).unwrap();
    std::fs::write(
        trust_dir.join("known_hosts"),
        format!("127.0.0.1:{} {}\n", server.port, server.key_id),
    )
    .unwrap();
}

fn client_config(port: u16, timeout_secs: u64, password: &str) -> SshConfig {
    SshConfig {
        host: "127.0.0.1".to_string(),
        port,
        username: "scanner".to_string(),
        auth: SshAuth::Password {
            password: password.to_string(),
        },
        timeout_secs,
    }
}

struct HomeGuard {
    original: Option<std::ffi::OsString>,
}

impl HomeGuard {
    fn set(path: &Path) -> Self {
        let original = std::env::var_os("HOME");
        std::env::set_var("HOME", path);
        Self { original }
    }
}

impl Drop for HomeGuard {
    fn drop(&mut self) {
        if let Some(original) = &self.original {
            std::env::set_var("HOME", original);
        } else {
            std::env::remove_var("HOME");
        }
    }
}

async fn execute_case(home: &Path, behavior: Behavior, timeout_secs: u64) -> CommandEvidence {
    let server = start_server(behavior, true).await;
    trust_server(home, &server);
    collect_plan(
        &client_config(server.port, timeout_secs, "correct-password"),
        &probe_plan(),
    )
    .await
    .commands
    .remove(0)
}

fn probe_plan() -> CollectionPlan {
    CollectionPlan {
        platform: CheckPlatform::Bsd,
        check_definitions_sha256: "test-checks".to_string(),
        commands: vec![CollectionCommand {
            command: "collect".to_owned(),
            data_key: "probe".to_owned(),
            accepted_exit_codes: vec![0],
            output_policy: OutputPolicy::Any,
        }],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_transport_and_failure_injection_matrix() {
    let home = TempDir::new().unwrap();
    let _home_guard = HomeGuard::set(home.path());

    assert_host_key_policy(home.path()).await;

    let untrusted_server = start_server(Behavior::Success, true).await;
    let record = collect_plan(
        &client_config(untrusted_server.port, 2, "correct-password"),
        &probe_plan(),
    )
    .await
    .commands
    .remove(0);
    assert!(
        record.status == CommandStatus::TransportError
            && record
                .error
                .as_deref()
                .is_some_and(|error| error.contains("SSH connection failed")),
        "unexpected record: {record:?}"
    );

    let changed_server = start_server(Behavior::Success, true).await;
    std::fs::create_dir_all(home.path().join(".automatestig")).unwrap();
    std::fs::write(
        home.path().join(".automatestig/known_hosts"),
        format!(
            "127.0.0.1:{} SHA256:not-the-server-key\n",
            changed_server.port
        ),
    )
    .unwrap();
    let record = collect_plan(
        &client_config(changed_server.port, 2, "correct-password"),
        &probe_plan(),
    )
    .await
    .commands
    .remove(0);
    assert!(
        record.status == CommandStatus::TransportError
            && record
                .error
                .as_deref()
                .is_some_and(|error| error.contains("SSH connection failed")),
        "unexpected record: {record:?}"
    );

    let record = execute_case(home.path(), Behavior::Success, 2).await;
    assert_eq!(record.status, CommandStatus::Success);
    assert_eq!(record.stdout, "collected-value\n");

    let record = execute_case(home.path(), Behavior::NonzeroWithStderr, 2).await;
    assert_eq!(record.status, CommandStatus::ExitFailure);
    let error = record.error.unwrap();
    assert!(error.contains("status 17"), "unexpected error: {error}");
    assert!(
        error.contains("permission denied"),
        "unexpected error: {error}"
    );

    let record = execute_case(home.path(), Behavior::MissingExitStatus, 2).await;
    assert_eq!(record.status, CommandStatus::MissingExitStatus);
    let error = record.error.unwrap();
    assert!(
        error.contains("without an exit status"),
        "unexpected error: {error}"
    );

    let record = execute_case(home.path(), Behavior::DisconnectAfterPartialOutput, 2).await;
    assert_eq!(record.status, CommandStatus::MissingExitStatus);
    let error = record.error.unwrap();
    assert!(
        error.contains("without an exit status"),
        "unexpected error: {error}"
    );

    let record = execute_case(home.path(), Behavior::InvalidUtf8, 2).await;
    assert_eq!(record.status, CommandStatus::ProtocolError);
    let error = record.error.unwrap();
    assert!(
        error.contains("not valid UTF-8"),
        "unexpected error: {error}"
    );

    let record = execute_case(home.path(), Behavior::OversizedOutput, 10).await;
    assert_eq!(record.status, CommandStatus::OutputLimit);
    let error = record.error.unwrap();
    assert!(
        error.contains("52428800-byte safety limit"),
        "unexpected error: {error}"
    );

    let started = Instant::now();
    let record = execute_case(home.path(), Behavior::Stall, 1).await;
    assert!(matches!(
        record.status,
        CommandStatus::Timeout | CommandStatus::MissingExitStatus
    ));
    let error = record.error.unwrap();
    assert!(
        error.contains("timed out") || error.contains("without an exit status"),
        "unexpected error: {error}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "inactivity timeout did not terminate the stalled command"
    );

    let server = start_server(Behavior::Success, false).await;
    trust_server(home.path(), &server);
    let record = collect_plan(
        &client_config(server.port, 2, "wrong-password"),
        &probe_plan(),
    )
    .await
    .commands
    .remove(0);
    assert!(
        record.status == CommandStatus::TransportError
            && record
                .error
                .as_deref()
                .is_some_and(|error| error.contains("authentication failed")),
        "unexpected record: {record:?}"
    );
}

async fn assert_host_key_policy(home: &Path) {
    let host = "device.example.test";
    let port = 2222;
    let first_key =
        PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519).unwrap();
    let changed_key =
        PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519).unwrap();

    let mut unknown = SshHandler::new(host, port).with_accept_unknown(false);
    assert!(
        !russh::client::Handler::check_server_key(&mut unknown, first_key.public_key())
            .await
            .unwrap()
    );

    let mut enrollment = SshHandler::new(host, port).with_accept_unknown(true);
    assert!(
        russh::client::Handler::check_server_key(&mut enrollment, first_key.public_key())
            .await
            .unwrap()
    );

    let mut known = SshHandler::new(host, port).with_accept_unknown(false);
    assert!(
        russh::client::Handler::check_server_key(&mut known, first_key.public_key())
            .await
            .unwrap()
    );

    let mut changed = SshHandler::new(host, port).with_accept_unknown(false);
    assert!(
        !russh::client::Handler::check_server_key(&mut changed, changed_key.public_key())
            .await
            .unwrap()
    );

    assert!(home.join(".automatestig/known_hosts").is_file());
}
