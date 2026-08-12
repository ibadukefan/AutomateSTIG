//! AutomateSTIG CLI — difficult-device STIG scanning and evidence handoff.
//!
//! Usage:
//!   automatestig collect --stig <STIG_ID> --host <HOST> --username <USER> --output <ADAPTER_EVIDENCE_JSON>
//!   automatestig evaluate --stig <STIG_ID> (--evidence <FILE> | --config <FILE>) [--output <OUTPUT>]
//!   automatestig scanner verify-handoff <HANDOFF_ZIP>

mod commands;
mod ui;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "automatestig",
    version,
    about = "AutomateSTIG — difficult-device STIG scanner and evidence handoff",
    long_about = "AutomateSTIG is a deterministic, air-gapped-first scanner and evidence producer that supplements STIG Manager.\n\
                   Its v0.3 scanner targets are NetApp ONTAP 9.x and FreeBSD over\n\
                   plan-bound SSH evidence, plus Cisco IOS-XE Router NDM running configs.\n\n\
                   Changed reviews use a verified selected-run handoff; connected verification records only an exact remote no-op.\n\n\
                   Evaluation is deterministic and reproducible."
)]
struct Cli {
    /// Enable verbose output.
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Database path (default: ~/.automatestig/data.db).
    // Retained only so artifact-output safety can recognize an explicitly
    // relocated managed database. It is not part of the scanner user flow.
    #[arg(long, global = true, hide = true)]
    db: Option<String>,

    /// STIG library path (default: ~/.automatestig/library).
    // Retained only as a managed-path exclusion boundary. Normal scanner
    // content is immutable and release-bundled, not selected from this path.
    #[arg(long, global = true, hide = true)]
    library: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[cfg(test)]
impl Cli {
    fn command_test_fixture(library: String, db: String) -> Self {
        Self {
            verbose: false,
            library: Some(library),
            db: Some(db),
            command: Commands::Status,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Collect native, replayable adapter evidence from a remote device over SSH.
    Collect {
        /// Release-bundled scanner profile ID or exact STIG ID.
        #[arg(short, long)]
        stig: String,

        /// Remote host name or address (without username).
        #[arg(long)]
        host: String,

        /// Corroborating device hostname; when supplied, must equal the observed device identity.
        #[arg(long)]
        hostname: Option<String>,

        /// SSH username.
        #[arg(short, long)]
        username: String,

        /// SSH port.
        #[arg(long, default_value_t = 22)]
        port: u16,

        /// Private-key file; when absent, password is read from --password-env.
        #[arg(long)]
        key: Option<String>,

        /// Environment variable containing the SSH password.
        #[arg(long, default_value = "AUTOMATESTIG_SSH_PASSWORD")]
        password_env: String,

        /// Environment variable containing the private-key passphrase.
        #[arg(long, default_value = "AUTOMATESTIG_SSH_KEY_PASSPHRASE")]
        passphrase_env: String,

        /// Per-command wall-clock and inactivity timeout.
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,

        /// Native adapter-evidence JSON path, or '-' for stdout.
        #[arg(short, long)]
        output: String,

        /// Enroll an unknown server key for this collection only.
        #[arg(long)]
        trust_on_first_use: bool,
    },

    /// Evaluate a bundled profile against native adapter evidence or a running configuration.
    Evaluate {
        /// Release-bundled scanner profile ID or exact STIG ID.
        #[arg(short, long)]
        stig: String,

        /// Native adapter-evidence JSON produced by `automatestig collect`.
        #[arg(long, required_unless_present = "config", conflicts_with = "config")]
        evidence: Option<String>,

        /// Authorized IOS-XE complete running configuration.
        #[arg(
            long,
            required_unless_present = "evidence",
            conflicts_with = "evidence"
        )]
        config: Option<String>,

        /// Signed organization-policy JSON for organization-defined Cisco controls.
        #[arg(long, requires = "organization_policy_signature")]
        organization_policy: Option<String>,

        /// Detached Ed25519 signature for --organization-policy.
        #[arg(long, requires = "organization_policy")]
        organization_policy_signature: Option<String>,

        /// Corroborating hostname; must match the identity inside the input.
        #[arg(long)]
        host: Option<String>,

        /// Output file path (.json native result, or supplemental .cklb).
        #[arg(short, long)]
        output: Option<String>,

        /// Output format override (json or cklb).
        #[arg(short, long)]
        format: Option<String>,
    },

    /// Import a .stigpack content pack into the STIG library.
    #[cfg(feature = "maintainer")]
    #[command(hide = true)]
    Import {
        /// Path to the .stigpack file.
        #[arg(short, long)]
        pack: String,
    },

    /// Verify a .stigpack file without importing.
    #[cfg(feature = "maintainer")]
    #[command(hide = true)]
    Verify {
        /// Path to the .stigpack file.
        #[arg(short, long)]
        pack: String,
    },

    /// Manage the STIG library.
    #[cfg(feature = "maintainer")]
    #[command(hide = true)]
    Library {
        #[command(subcommand)]
        action: LibraryAction,
    },

    /// Explicitly create a new external content-signing key pair.
    #[cfg(feature = "maintainer")]
    #[command(name = "generate-signing-key", hide = true)]
    GenerateSigningKey {
        /// Output path for the private key; the public key uses `.pub`.
        #[arg(long)]
        output: String,
    },

    /// Sign an organization-policy artifact on an isolated signing host.
    #[cfg(feature = "maintainer")]
    #[command(name = "sign-organization-policy", hide = true)]
    SignOrganizationPolicy {
        /// Exact organization-policy JSON bytes to sign.
        #[arg(long)]
        policy: String,

        /// Existing external raw 32-byte Ed25519 private key.
        #[arg(long)]
        signing_key: String,

        /// Create-new detached signature output.
        #[arg(short, long)]
        output: String,
    },

    /// Build a .stigpack content pack.
    #[cfg(feature = "maintainer")]
    #[command(name = "build-pack", hide = true)]
    BuildPack {
        /// Pack ID.
        #[arg(long)]
        id: String,

        /// Pack name.
        #[arg(long)]
        name: String,

        /// Pack version.
        #[arg(long)]
        version: String,

        /// Directory containing benchmarks/ and other pack content.
        #[arg(short, long)]
        source: String,

        /// Output .stigpack file path.
        #[arg(short, long)]
        output: String,

        /// Existing external raw 32-byte Ed25519 signing key.
        ///
        /// The matching public key must exist at the same path with a `.pub`
        /// extension. AutomateSTIG never creates either key during pack build.
        #[arg(long)]
        signing_key: String,
    },

    /// Import DISA STIG content directly from XCCDF files or ZIP archives.
    #[cfg(feature = "maintainer")]
    #[command(name = "disa-import", hide = true)]
    DisaImport {
        /// Path to DISA STIG ZIP archive or XCCDF XML file.
        #[arg(short, long)]
        input: String,
    },

    /// Validate rule-by-rule coverage manifests.
    #[cfg(feature = "maintainer")]
    #[command(hide = true)]
    Coverage {
        #[command(subcommand)]
        action: CoverageAction,
    },

    /// Inspect scanner artifacts exchanged with an existing STIG Manager workflow.
    Scanner {
        #[command(subcommand)]
        action: ScannerAction,
    },

    /// Verify and show the release-bundled scanner contract.
    Status,
}

#[cfg(feature = "maintainer")]
#[derive(Debug, Subcommand)]
enum CoverageAction {
    /// Validate a coverage manifest JSON file.
    Validate {
        /// Path to coverage manifest JSON.
        #[arg(short, long)]
        manifest: String,
    },
}

#[derive(Debug, Subcommand)]
enum ScannerAction {
    /// Verify a selected-run handoff ZIP without importing or changing local state.
    #[command(name = "verify-handoff")]
    VerifyHandoff {
        /// Selected-run handoff ZIP downloaded from AutomateSTIG.
        zip: String,

        /// Detached signature sidecar created on a protected signing host.
        #[arg(long)]
        signature: Option<String>,

        /// Dedicated directory of trusted handoff-producer `.pub` keys.
        #[arg(long, requires = "signature")]
        trust_dir: Option<String>,
    },
}

#[cfg(feature = "maintainer")]
#[derive(Debug, Subcommand)]
enum LibraryAction {
    /// List all available STIG benchmarks.
    List,

    /// Show details of a specific benchmark.
    Show {
        /// Benchmark ID.
        id: String,
    },

    /// Initialize a new STIG library.
    Init,
}

fn main() {
    let cli = Cli::parse();

    // Initialize logging.
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .with_target(false)
        .init();

    let result = match &cli.command {
        Commands::Collect {
            stig,
            host,
            hostname,
            username,
            port,
            key,
            password_env,
            passphrase_env,
            timeout_secs,
            output,
            trust_on_first_use,
        } => commands::collect::run(
            commands::collect::CollectArgs {
                stig_id: stig.clone(),
                host: host.clone(),
                hostname: hostname.clone(),
                username: username.clone(),
                port: *port,
                key: key.clone(),
                password_env: password_env.clone(),
                passphrase_env: passphrase_env.clone(),
                timeout_secs: *timeout_secs,
                output: output.clone(),
                trust_on_first_use: *trust_on_first_use,
            },
            &cli,
        ),
        Commands::Evaluate {
            ref stig,
            ref evidence,
            ref config,
            ref organization_policy,
            ref organization_policy_signature,
            ref host,
            ref output,
            ref format,
        } => commands::evaluate::run(
            commands::evaluate::EvaluateArgs {
                stig_id: stig.clone(),
                evidence: evidence.clone(),
                config: config.clone(),
                organization_policy: organization_policy.clone(),
                organization_policy_signature: organization_policy_signature.clone(),
                host: host.clone(),
                output: output.clone(),
                format: format.clone(),
            },
            &cli,
        ),
        #[cfg(feature = "maintainer")]
        Commands::Import { ref pack } => commands::import::run(pack, &cli),
        #[cfg(feature = "maintainer")]
        Commands::Verify { ref pack } => commands::verify::run(pack),
        #[cfg(feature = "maintainer")]
        Commands::Library { ref action } => match action {
            LibraryAction::List => commands::library::list(&cli),
            LibraryAction::Show { ref id } => commands::library::show(id, &cli),
            LibraryAction::Init => commands::library::init(&cli),
        },
        #[cfg(feature = "maintainer")]
        Commands::GenerateSigningKey { ref output } => {
            commands::build_pack::generate_signing_key(output)
        }
        #[cfg(feature = "maintainer")]
        Commands::SignOrganizationPolicy {
            ref policy,
            ref signing_key,
            ref output,
        } => commands::evaluate::sign_organization_policy(policy, signing_key, output),
        #[cfg(feature = "maintainer")]
        Commands::BuildPack {
            ref id,
            ref name,
            ref version,
            ref source,
            ref output,
            ref signing_key,
        } => commands::build_pack::run(id, name, version, source, output, signing_key),
        #[cfg(feature = "maintainer")]
        Commands::DisaImport { ref input } => commands::disa_import::run(input, &cli),
        #[cfg(feature = "maintainer")]
        Commands::Coverage { ref action } => match action {
            CoverageAction::Validate { ref manifest } => commands::coverage::validate(manifest),
        },
        Commands::Scanner { ref action } => match action {
            ScannerAction::VerifyHandoff {
                ref zip,
                ref signature,
                ref trust_dir,
            } => commands::handoff::run(zip, signature.as_deref(), trust_dir.as_deref()),
        },
        Commands::Status => commands::status::run(&cli),
    };

    if let Err(e) = result {
        ui::error(&format!("{:#}", e));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::{error::ErrorKind, CommandFactory, Parser};

    #[test]
    fn product_help_exposes_only_scanning_and_read_only_handoff() {
        let help = Cli::command().render_long_help().to_string();
        for command in ["collect", "evaluate", "scanner", "status"] {
            assert!(help.contains(command), "missing scanner command {command}");
        }
        for retired in [
            "gen-answer",
            "convert",
            "summary",
            "disa-import",
            "library",
            "export",
            "migration",
            "sign-handoff",
            "generate-signing-key",
        ] {
            let command_is_listed = help.lines().any(|line| {
                line.trim_start()
                    .strip_prefix(retired)
                    .is_some_and(|suffix| suffix.chars().next().is_some_and(char::is_whitespace))
            });
            assert!(
                !command_is_listed,
                "manager-duplicate command leaked: {retired}"
            );
        }
    }

    #[test]
    fn manager_duplicate_commands_are_not_compiled_into_the_product_cli() {
        for retired in ["convert", "summary", "gen-answer", "export"] {
            let error = Cli::try_parse_from(["automatestig", retired])
                .expect_err("retired manager command unexpectedly parsed");
            assert_eq!(error.kind(), ErrorKind::InvalidSubcommand, "{retired}");
        }
    }

    #[cfg(not(feature = "maintainer"))]
    #[test]
    fn protected_maintainer_commands_are_absent_from_the_product_build() {
        for command in [
            "import",
            "verify",
            "library",
            "build-pack",
            "disa-import",
            "coverage",
            "generate-signing-key",
            "sign-organization-policy",
        ] {
            let error = Cli::try_parse_from(["automatestig", command])
                .expect_err("maintainer command unexpectedly parsed in product build");
            assert_eq!(error.kind(), ErrorKind::InvalidSubcommand, "{command}");
        }
    }

    #[test]
    fn evaluate_requires_exactly_one_primary_input() {
        let missing = match Cli::try_parse_from(["automatestig", "evaluate", "--stig", "example"]) {
            Err(error) => error,
            Ok(_) => panic!("an evaluation without an input must be rejected"),
        };
        assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);

        let mixed = match Cli::try_parse_from([
            "automatestig",
            "evaluate",
            "--stig",
            "example",
            "--evidence",
            "evidence.json",
            "--config",
            "running-config.txt",
        ]) {
            Err(error) => error,
            Ok(_) => panic!("evidence and config must be mutually exclusive"),
        };
        assert_eq!(mixed.kind(), ErrorKind::ArgumentConflict);

        assert!(Cli::try_parse_from([
            "automatestig",
            "evaluate",
            "--stig",
            "example",
            "--evidence",
            "evidence.json",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "automatestig",
            "evaluate",
            "--stig",
            "example",
            "--config",
            "running-config.txt",
        ])
        .is_ok());
    }

    #[test]
    fn legacy_evaluation_mutations_are_not_compiled_into_the_product_cli() {
        for option in ["--allow-legacy-evidence", "--answer", "--merge"] {
            let mut arguments = vec![
                "automatestig",
                "evaluate",
                "--stig",
                "example",
                "--evidence",
                "evidence.json",
                option,
            ];
            if matches!(option, "--answer" | "--merge") {
                arguments.push("legacy.json");
            }
            let error = Cli::try_parse_from(arguments)
                .expect_err("legacy evaluation mutation unexpectedly parsed");
            assert_eq!(error.kind(), ErrorKind::UnknownArgument, "{option}");
        }
    }

    #[test]
    fn scanner_handoff_verification_uses_a_positional_read_only_artifact() {
        assert!(Cli::try_parse_from([
            "automatestig",
            "scanner",
            "verify-handoff",
            "selected-run.zip",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "automatestig",
            "scanner",
            "verify-handoff",
            "selected-run.zip",
            "--signature",
            "selected-run.zip.signature.json",
            "--trust-dir",
            "/approved/handoff-keys",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "automatestig",
            "scanner",
            "verify-handoff",
            "selected-run.zip",
            "--trust-dir",
            "/approved/handoff-keys",
        ])
        .is_err());
        assert!(Cli::try_parse_from(["automatestig", "scanner", "verify-handoff"]).is_err());
        for protected in ["sign-handoff", "generate-signing-key"] {
            let error = Cli::try_parse_from(["automatestig", "scanner", protected])
                .expect_err("protected handoff mutation leaked into product CLI");
            assert_eq!(error.kind(), ErrorKind::InvalidSubcommand);
        }
        let migration = Cli::try_parse_from(["automatestig", "migration"])
            .expect_err("transition migration leaked into product CLI");
        assert_eq!(migration.kind(), ErrorKind::InvalidSubcommand);
    }
}
