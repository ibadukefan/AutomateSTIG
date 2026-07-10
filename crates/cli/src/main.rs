//! AutomateSTIG CLI — STIG evaluation and compliance automation.
//!
//! Usage:
//!   automatestig evaluate --stig <STIG_ID> [--scan <SCAN_FILE>] [--evidence <EVIDENCE_FILE>] [--answer <ANSWER_FILE>] [--output <OUTPUT>]
//!   automatestig import --pack <STIGPACK_FILE>
//!   automatestig library list
//!   automatestig convert --input <FILE> --format <ckl|cklb|json>
//!   automatestig verify --pack <STIGPACK_FILE>
//!   automatestig summary --input <CKL_FILE>

mod commands;
pub mod ui;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "automatestig",
    version,
    about = "AutomateSTIG — Cross-platform STIG evaluation and compliance automation",
    long_about = "AutomateSTIG is a deterministic, air-gapped-first STIG evaluation platform.\n\
                   It automates checklist population from scan results, provides a robust\n\
                   answer file system, and generates audit-ready compliance artifacts.\n\n\
                   All operations are 100% deterministic and reproducible."
)]
struct Cli {
    /// Enable verbose output.
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Database path (default: ~/.automatestig/data.db).
    #[arg(long, global = true)]
    db: Option<String>,

    /// STIG library path (default: ~/.automatestig/library).
    #[arg(long, global = true)]
    library: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Evaluate a STIG against scan results and answer files.
    Evaluate {
        /// STIG benchmark ID to evaluate.
        #[arg(short, long)]
        stig: String,

        /// Path to scan result file (XCCDF, CKL, or config dump).
        #[arg(short = 'S', long)]
        scan: Option<String>,

        /// Evidence transcript file collected from the target device (### automatestig:command format).
        #[arg(long)]
        evidence: Option<String>,

        /// Device running-config file (e.g. show running-config output) evaluated via config_line check packs.
        #[arg(long)]
        config: Option<String>,

        /// Path(s) to answer file(s) (JSON/YAML).
        #[arg(short, long)]
        answer: Vec<String>,

        /// Target hostname (auto-detected from scan if not specified).
        #[arg(long)]
        host: Option<String>,

        /// Output file path (.ckl, .cklb, or .json).
        #[arg(short, long)]
        output: Option<String>,

        /// Output format override (ckl, cklb, json).
        #[arg(short, long)]
        format: Option<String>,

        /// Merge with previous checklist (preserves manual entries).
        #[arg(long)]
        merge: Option<String>,
    },

    /// Import a .stigpack content pack into the STIG library.
    Import {
        /// Path to the .stigpack file.
        #[arg(short, long)]
        pack: String,
    },

    /// Verify a .stigpack file without importing.
    Verify {
        /// Path to the .stigpack file.
        #[arg(short, long)]
        pack: String,
    },

    /// Manage the STIG library.
    Library {
        #[command(subcommand)]
        action: LibraryAction,
    },

    /// Convert between checklist formats.
    Convert {
        /// Input file path.
        #[arg(short, long)]
        input: String,

        /// Output file path.
        #[arg(short, long)]
        output: String,

        /// Output format (ckl, cklb, json, stig-manager).
        #[arg(short, long)]
        format: Option<String>,
    },

    /// Show summary of a checklist or scan result.
    Summary {
        /// Input file path (.ckl, .cklb, or .json).
        #[arg(short, long)]
        input: String,

        /// Show only open findings.
        #[arg(long)]
        open_only: bool,

        /// Filter by severity (high, medium, low).
        #[arg(long)]
        severity: Option<String>,
    },

    /// Generate an answer file template from an existing checklist.
    #[command(name = "gen-answer")]
    GenAnswer {
        /// Input checklist file.
        #[arg(short, long)]
        input: String,

        /// Output answer file path (.json or .yaml).
        #[arg(short, long)]
        output: String,

        /// Include Not_Reviewed findings in template.
        #[arg(long)]
        include_unreviewed: bool,
    },

    /// Export checklist to external formats.
    Export {
        /// Input checklist file.
        #[arg(short, long)]
        input: String,

        /// Output file path.
        #[arg(short, long)]
        output: String,

        /// Export format (stig-manager).
        #[arg(short, long)]
        format: String,

        /// Collection name (for STIG-Manager export).
        #[arg(long)]
        collection: Option<String>,
    },

    /// Build a .stigpack content pack.
    #[command(name = "build-pack")]
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
    },

    /// Import DISA STIG content directly from XCCDF files or ZIP archives.
    #[command(name = "disa-import")]
    DisaImport {
        /// Path to DISA STIG ZIP archive or XCCDF XML file.
        #[arg(short, long)]
        input: String,
    },

    /// Validate rule-by-rule coverage manifests.
    Coverage {
        #[command(subcommand)]
        action: CoverageAction,
    },

    /// Show application version and library status.
    Status,
}

#[derive(Subcommand)]
enum CoverageAction {
    /// Validate a coverage manifest JSON file.
    Validate {
        /// Path to coverage manifest JSON.
        #[arg(short, long)]
        manifest: String,
    },
}

#[derive(Subcommand)]
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
        Commands::Evaluate {
            ref stig,
            ref scan,
            ref evidence,
            ref config,
            ref answer,
            ref host,
            ref output,
            ref format,
            ref merge,
        } => commands::evaluate::run(
            commands::evaluate::EvaluateArgs {
                stig_id: stig.clone(),
                scan: scan.clone(),
                evidence: evidence.clone(),
                config: config.clone(),
                answer_paths: answer.clone(),
                host: host.clone(),
                output: output.clone(),
                format: format.clone(),
                merge: merge.clone(),
            },
            &cli,
        ),
        Commands::Import { ref pack } => commands::import::run(pack, &cli),
        Commands::Verify { ref pack } => commands::verify::run(pack),
        Commands::Library { ref action } => match action {
            LibraryAction::List => commands::library::list(&cli),
            LibraryAction::Show { ref id } => commands::library::show(id, &cli),
            LibraryAction::Init => commands::library::init(&cli),
        },
        Commands::Convert {
            ref input,
            ref output,
            ref format,
        } => commands::convert::run(input, output, format.as_deref()),
        Commands::Summary {
            ref input,
            open_only,
            ref severity,
        } => commands::summary::run(input, *open_only, severity.as_deref()),
        Commands::GenAnswer {
            ref input,
            ref output,
            include_unreviewed,
        } => commands::gen_answer::run(input, output, *include_unreviewed),
        Commands::Export {
            ref input,
            ref output,
            ref format,
            ref collection,
        } => commands::export::run(input, output, format, collection.as_deref()),
        Commands::BuildPack {
            ref id,
            ref name,
            ref version,
            ref source,
            ref output,
        } => commands::build_pack::run(id, name, version, source, output),
        Commands::DisaImport { ref input } => commands::disa_import::run(input, &cli),
        Commands::Coverage { ref action } => match action {
            CoverageAction::Validate { ref manifest } => commands::coverage::validate(manifest),
        },
        Commands::Status => commands::status::run(&cli),
    };

    if let Err(e) = result {
        ui::error(&format!("{:#}", e));
        std::process::exit(1);
    }
}
