use std::{
    io::{Cursor, Read},
    time::Duration,
};

use bon::{bon, Builder};
use byteorder::{LittleEndian, WriteBytesExt};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Parser, Subcommand};
use fs_err as fs;
use log::{debug, info, warn};
use miette::{Diagnostic, Report};
use simplelog::{ColorChoice, TermLogger, TerminalMode};
use snafu::{OptionExt, Snafu};
use tokio::task::spawn_blocking;
use vex_v5_serial::{
    commands::file::{
        compress, LinkedFile, Program as ProgramIni, ProgramIniConfig, Project, UploadFile,
        DEFAULT_LIB_ADDRESS, PROGRAM_START_ADDRESS,
    },
    connection::{
        serial::{self, SerialConnection, SerialError},
        Connection,
    },
    packets::file::FileExitAction,
    string::FixedLengthString,
};

/// Uploads can fail with files bigger than 4mb.
const PROBABLY_WONT_UPLOAD_SIZE: usize = 4 * 1024 * 1024;

#[derive(Debug, Snafu, Diagnostic)]
enum CliError {
    #[snafu(transparent)]
    #[diagnostic(code(hydrozoa::serial))]
    Serial { source: serial::SerialError },

    #[snafu(transparent)]
    #[diagnostic(code(hydrozoa::io))]
    Io { source: std::io::Error },

    /// No V5 devices found.
    #[diagnostic(
        code(hydrozoa::disconnected),
        help("Ensure that a V5 brain or controller is plugged in and powered on with a stable USB connection, then try again.")
    )]
    NoDevice,
}

#[derive(Debug, Snafu, Diagnostic)]
#[diagnostic(severity(Warning))]
enum CliWarning {
    /// This program is larger than 4 MB, which may cause the upload to fail.
    #[diagnostic(code(hydrozoa::too_large))]
    ProgramTooLarge,
}

impl CliWarning {
    pub fn emit(self) {
        warn!("{:?}", Report::new(self));
    }
}

type Result<T, E = CliError> = std::result::Result<T, E>;

/// A simple CLI application
#[derive(Parser)]
#[command(version, author, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    Upload {
        /// The program to use
        input: Utf8PathBuf,

        #[arg(short, long)]
        slot: u8,

        /// The runtime to use
        #[arg(short, long)]
        runtime: Utf8PathBuf,
    },
}

#[tokio::main]
async fn main() -> miette::Result<()> {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        simplelog::LevelFilter::Debug
    } else {
        simplelog::LevelFilter::Warn
    };
    TermLogger::init(
        filter,
        Default::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .unwrap();

    run_command(cli.command).await?;

    Ok(())
}

async fn run_command(command: Command) -> Result<()> {
    match command {
        Command::Upload {
            input,
            runtime,
            slot,
        } => {
            let user_program = create_program_payload(&input)?;
            if user_program.len() > PROBABLY_WONT_UPLOAD_SIZE {
                CliWarning::ProgramTooLarge.emit();
            }

            let mut device = open_connection().await?;

            let program = Program::builder()
                .slot(slot)
                .runtime(fs::read(&runtime)?)
                .runtime_name("libmutliv_runtime.bin".to_string())
                .user_program(user_program)
                .build();

            program
                .upload(&mut device)
                .on_ini_progress(Box::new(|prog| {
                    println!("Uploading ini file: {:.2}%", prog);
                }))
                .on_bin_progress(Box::new(|prog| {
                    println!("Uploading bin file: {:.2}%", prog);
                }))
                .on_lib_progress(Box::new(|prog| {
                    println!("Uploading lib file: {:.2}%", prog);
                }))
                .call()
                .await?;
        }
    }

    Ok(())
}

/// Open a connection to the first V5 device found.
async fn open_connection() -> Result<SerialConnection> {
    let devices = serial::find_devices()?;

    debug!("Found {} devices", devices.len());
    for (n, device) in devices.iter().enumerate() {
        debug!("* Device {n}:");
        debug!("  - User Port: {:?}", device.user_port());
        debug!("  - System Port: {:?}", device.system_port());
    }

    spawn_blocking(move || {
        let device = devices.first().context(NoDeviceSnafu)?;
        info!("Connecting to device #0");
        Ok(device.connect(Duration::from_secs(5))?)
    })
    .await
    .unwrap()
}

/// Create the user program payload that will be sent to the V5 device.
///
/// The payload begins with a 4-byte header that contains the length of the
/// program file. The rest of the payload is the file data.
///
/// When the V5 program starts, it will read the payload from memory to
/// determine the behavior of the program. The format of the payload data itself
/// is specific to the runtime, but is always loaded into memory at a fixed
/// address (see [`HOT_START`]).
fn create_program_payload(program: &Utf8Path) -> Result<Vec<u8>> {
    const HEADER_SIZE: usize = size_of::<u32>();

    let mut payload = Vec::<u8>::with_capacity(HEADER_SIZE);
    // The real header data is added after the file is written into the payload.
    payload.write_u32::<LittleEndian>(0).unwrap();

    let mut program = fs::File::open(program)?;
    program.read_to_end(&mut payload)?;

    let file_len = payload.len() - HEADER_SIZE;

    let mut payload = Cursor::new(payload);
    assert_eq!(payload.position(), 0);
    payload.write_u32::<LittleEndian>(file_len as u32)?;
    Ok(payload.into_inner())
}

#[derive(Debug, Builder)]
struct Program {
    pub slot: u8,
    pub runtime: Vec<u8>,
    pub runtime_name: String,
    pub user_program: Vec<u8>,
}

#[bon]
impl Program {
    #[builder]
    pub async fn upload(
        #[allow(unused_mut)] mut self,
        #[builder(start_fn)] device: &mut SerialConnection,
        on_ini_progress: Option<Box<dyn FnMut(f32) + Send>>,
        on_bin_progress: Option<Box<dyn FnMut(f32) + Send>>,
        on_lib_progress: Option<Box<dyn FnMut(f32) + Send>>,
    ) -> Result<(), SerialError> {
        let base_file_name = format!("slot_{}", self.slot - 1);

        info!("Uploading program ini file");

        let ini = ProgramIniConfig {
            program: ProgramIni {
                description: "Description".to_string(),
                icon: "USER0001x".to_string(),
                iconalt: String::new(),
                slot: self.slot,
                name: "Name".to_string(),
            },
            project: Project {
                ide: "Hydrozoa".to_string(),
            },
        };

        device
            .execute_command(UploadFile {
                filename: FixedLengthString::new(format!("{base_file_name}.ini"))?,
                filetype: FixedLengthString::new("ini".to_string())?,
                vendor: None,
                data: serde_ini::to_vec(&ini).unwrap(),
                target: None,
                load_addr: PROGRAM_START_ADDRESS,
                linked_file: None,
                after_upload: FileExitAction::DoNothing,
                progress_callback: on_ini_progress,
            })
            .await?;

        let program_bin_name = format!("{base_file_name}.bin");

        info!("Uploading library binary");

        debug!("Compressing library binary");
        compress(&mut self.runtime);
        debug!("Compression complete");

        device
            .execute_command(UploadFile {
                filename: FixedLengthString::new(self.runtime_name.clone())?,
                filetype: FixedLengthString::new("bin".to_string())?,
                vendor: None,
                data: self.runtime,
                target: None,
                load_addr: PROGRAM_START_ADDRESS,
                linked_file: None,
                after_upload: FileExitAction::DoNothing,
                progress_callback: on_lib_progress,
            })
            .await?;

        info!("Uploading program binary");

        debug!("Compressing program binary");
        compress(&mut self.user_program);
        debug!("Compression complete");

        // Only ask the brain to link to a library if the program expects it.
        // Monolith programs don't have libraries.
        info!("Program will be linked to library: {:?}", self.runtime_name);
        let linked_file = LinkedFile {
            filename: FixedLengthString::new(self.runtime_name)?,
            vendor: None,
        };

        device
            .execute_command(UploadFile {
                filename: FixedLengthString::new(program_bin_name)?,
                filetype: FixedLengthString::new("bin".to_string())?,
                vendor: None,
                data: self.user_program,
                target: None,
                load_addr: DEFAULT_LIB_ADDRESS,
                linked_file: Some(linked_file),
                after_upload: FileExitAction::DoNothing,
                progress_callback: on_bin_progress,
            })
            .await?;

        Ok(())
    }
}
