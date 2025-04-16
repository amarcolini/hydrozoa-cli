use std::{
    io::{Cursor, Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use byteorder::{LittleEndian, WriteBytesExt};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{error::ErrorKind, CommandFactory, Parser, Subcommand};
use flate2::{Compression, GzBuilder};
use fs_err as fs;
use log::warn;
use miette::{Diagnostic, Report};
use simplelog::{ColorChoice, TermLogger, TerminalMode};
use snafu::Snafu;
use tokio::spawn;

use cargo_v5::{
    commands::{
        rm::rm,
        upload::{AfterUpload, ProgramIcon},
    },
    connection::{open_connection, switch_radio_channel},
    errors::CliError,
};

use vex_v5_serial::{
    commands::file::{
        LinkedFile, Program, ProgramIniConfig, Project, UploadFile, PROS_HOT_BIN_LOAD_ADDR,
        USER_PROGRAM_LOAD_ADDR,
    },
    connection::{
        serial::{SerialConnection, SerialError},
        Connection,
    },
    crc::VEX_CRC32,
    packets::{
        cdc2::Cdc2Ack,
        file::{
            ExtensionType, FileExitAction, FileInitAction, FileInitOption, FileMetadata,
            FileTransferTarget, FileVendor, GetDirectoryEntryPacket, GetDirectoryEntryPayload,
            GetDirectoryEntryReplyPacket, GetDirectoryFileCountPacket,
            GetDirectoryFileCountPayload, GetDirectoryFileCountReplyPacket, GetFileMetadataPacket,
            GetFileMetadataPayload, GetFileMetadataReplyPacket, GetFileMetadataReplyPayload,
            InitFileTransferPacket, InitFileTransferPayload, InitFileTransferReplyPacket,
        },
        radio::RadioChannel,
    },
    string::FixedString,
    timestamp::j2000_timestamp,
    version::Version,
};

/// Uploads can fail with files bigger than 4mb.
const PROBABLY_WONT_UPLOAD_SIZE: usize = 4 * 1024 * 1024;

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
    /// Upload a Hydrozoa program.
    Upload {
        /// The program to use
        input: Utf8PathBuf,

        #[arg(short, long)]
        name: String,

        #[arg(short, long)]
        slot: u8,

        #[arg(short, long)]
        icon: Option<ProgramIcon>,

        /// Append a hash to the runtime name when uploading so that existing
        /// programs that depend on the runtime aren't broken.
        #[arg(long)]
        hash: bool,

        /// The version of the runtime in the format x.x.x.x, where x is between 0-255.
        /// This is used to know when to update it.
        #[arg(long)]
        version: Option<String>,

        /// The runtime to use
        #[arg(short, long)]
        runtime: Utf8PathBuf,
    },
    /// Manage installed Hydrozoa runtimes.
    #[command(subcommand)]
    Runtime(RuntimeCommand),
}

#[derive(Subcommand)]
enum RuntimeCommand {
    /// Lists all runtimes currently installed.
    List {},
    /// Removes all runtimes currently installed.
    /// This will break any existing Hydrozoa programs.
    Remove {},
}

#[tokio::main]
async fn main() -> miette::Result<()> {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        simplelog::LevelFilter::Debug
    } else {
        simplelog::LevelFilter::Error
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
            hash,
            version,
            name,
            icon,
        } => {
            let user_program = create_program_payload(&input)?;
            if user_program.len() > PROBABLY_WONT_UPLOAD_SIZE {
                CliWarning::ProgramTooLarge.emit();
            }

            let parsed_version: Version = version
                .map(|v| {
                    v.split('.')
                        .map(|i| {
                            let Ok(num) = i.parse::<u8>() else {
                                return Err(CliError::BadFieldType {
                                    field: String::from("version"),
                                    expected: String::from("integer between 0-255"),
                                    found: format!("\"{}\"", i),
                                });
                            };
                            Ok(num)
                        })
                        .collect::<Result<Vec<u8>, CliError>>()
                        .map(|nums| match nums.len() {
                            1..=4 => Ok(Version {
                                major: nums[0],
                                minor: *nums.get(1).unwrap_or(&0),
                                beta: *nums.get(1).unwrap_or(&0),
                                build: *nums.get(1).unwrap_or(&0),
                            }),
                            _ => Err(CliError::BadFieldType {
                                field: String::from("version"),
                                expected: String::from("1-4 version numbers"),
                                found: format!("{} version numbers", nums.len()),
                            }),
                        })
                })
                .map_or_else(
                    || -> Result<Version, CliError> {
                        Ok(Version {
                            major: 1,
                            minor: 0,
                            build: 0,
                            beta: 0,
                        })
                    },
                    |a| a.unwrap_or_else(Err),
                )
                .unwrap_or_else(|e| {
                    Cli::command()
                        .error(ErrorKind::InvalidValue, e.to_string())
                        .exit();
                });

            let runtime = fs::read(&runtime)?;
            let runtime_name = if hash {
                println!("Adding hash to runtime!");
                let mut hasher = blake3::Hasher::new();
                hasher.update(&runtime);
                let mut hash = [0; 8];
                hasher.finalize_xof().read_exact(&mut hash)?;
                format!("hz{}.bin", hex::encode(hash))
            } else {
                "libhydrozoa.bin".to_string()
            };

            // Ensure [1, 8] range bounds for slot number
            if !(1..=8).contains(&slot) {
                Err(CliError::SlotOutOfRange)?;
            }

            // Try to open a serialport in the background while we build.
            let connection_task = spawn(open_connection());

            // Wait for the serial port to finish opening.
            let mut connection = match connection_task.await {
                Ok(Ok(conn)) => conn,
                Ok(Err(_e)) => return Err(CliError::NoDevice),
                Err(_e) => return Err(CliError::NoDevice), // or whatever makes sense here
            };

            // Switch the radio to the download channel if the controller is wireless.
            switch_radio_channel(&mut connection, RadioChannel::Download).await?;

            upload_program(
                &mut connection,
                slot,
                icon.unwrap_or(ProgramIcon::AlienInUfo),
                name,
                runtime_name,
                user_program,
                runtime,
                parsed_version,
            )
            .await?
        }
        Command::Runtime(runtime_command) => {
            // Try to open a serialport in the background while we build.
            let connection_task = spawn(open_connection());

            // Wait for the serial port to finish opening.
            let mut connection = match connection_task.await {
                Ok(Ok(conn)) => conn,
                Ok(Err(_e)) => return Err(CliError::NoDevice),
                Err(_e) => return Err(CliError::NoDevice), // or whatever makes sense here
            };

            // Switch the radio to the download channel if the controller is wireless.
            switch_radio_channel(&mut connection, RadioChannel::Download).await?;

            match runtime_command {
                RuntimeCommand::List {} => {
                    for name in get_runtime_names(&mut connection).await? {
                        println!("{}", name);
                    }
                }
                RuntimeCommand::Remove {} => {
                    for name in get_runtime_names(&mut connection).await? {
                        print!("Removing file {}... ", name);
                        rm(&mut connection, PathBuf::from(format!("user/{}", name))).await?;
                        println!("Success!");
                    }
                }
            }
        }
    }

    Ok(())
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

async fn brain_file_metadata(
    connection: &mut SerialConnection,
    file_name: FixedString<23>,
    vendor: FileVendor,
) -> Result<Option<GetFileMetadataReplyPayload>, SerialError> {
    let reply = connection
        .packet_handshake::<GetFileMetadataReplyPacket>(
            Duration::from_millis(1000),
            2,
            GetFileMetadataPacket::new(GetFileMetadataPayload {
                vendor,
                option: 0,
                file_name,
            }),
        )
        .await?;
    match reply.ack {
        Cdc2Ack::NackProgramFile => Ok(None),
        Cdc2Ack::Ack => Ok(Some(if let Some(data) = reply.try_into_inner()? {
            data
        } else {
            return Ok(None);
        })),
        nack => Err(SerialError::Nack(nack)),
    }
}

async fn get_runtime_names(connection: &mut SerialConnection) -> Result<Vec<String>, SerialError> {
    let file_count = connection
        .packet_handshake::<GetDirectoryFileCountReplyPacket>(
            Duration::from_millis(200),
            2,
            GetDirectoryFileCountPacket::new(GetDirectoryFileCountPayload {
                vendor: FileVendor::User,
                option: 0,
            }),
        )
        .await?;
    let mut files = Vec::<String>::new();

    for i in 0..file_count.payload {
        let result = connection
            .packet_handshake::<GetDirectoryEntryReplyPacket>(
                Duration::from_millis(200),
                2,
                GetDirectoryEntryPacket::new(GetDirectoryEntryPayload {
                    file_index: i as u8,
                    unknown: 0,
                }),
            )
            .await?;

        if let Some(payload) = result.payload {
            if payload.file_name == "libhydrozoa.bin"
                || (payload.file_name.starts_with("hz") && payload.file_name.ends_with(".bin"))
            {
                files.push(payload.file_name);
            }
        }
    }
    Ok(files)
}

fn build_progress_callback(
    message: String,
    length: u16,
    progress: Arc<Mutex<Option<u16>>>,
) -> Box<dyn FnMut(f32) + Send> {
    Box::new(move |percent| {
        let mut progress = progress.try_lock().unwrap();
        if progress.is_none() {
            *progress = Some(0);
            println!("{}", message);
            for _ in 1..length {
                print!(".");
            }
            println!();
        }
        let new_progress = (percent / 100.0 * (length - 1) as f32).round() as u16;
        if new_progress > progress.unwrap() {
            for _ in 0..(new_progress - progress.unwrap()) {
                print!(":");
            }
            *progress = Some(new_progress);
        }
    })
}

/// Apply gzip compression to the given data
fn gzip_compress(data: &mut Vec<u8>) {
    let mut encoder = GzBuilder::new().write(Vec::new(), Compression::best());
    encoder.write_all(data).unwrap();
    *data = encoder.finish().unwrap();
}

pub async fn upload_program(
    connection: &mut SerialConnection,
    slot: u8,
    icon: ProgramIcon,
    name: String,
    runtime_name: String,
    mut user_program: Vec<u8>,
    mut runtime: Vec<u8>,
    runtime_version: Version,
) -> Result<(), CliError> {
    // Upload a program to the brain.
    let after = AfterUpload::ShowScreen; // Future cli option

    let slot_file_name = format!("slot_{}.bin", slot);
    let ini_file_name = format!("slot_{}.ini", slot);

    let ini_data = serde_ini::to_vec(&ProgramIniConfig {
        program: Program {
            description: String::from("Made with Hydrozoa"),
            icon: format!("USER{:03}x.bmp", icon as u16),
            iconalt: String::new(),
            slot: slot - 1,
            name,
        },
        project: Project {
            ide: String::from("Hydrozoa"),
        },
    })
    .unwrap();

    let needs_ini_upload = if let Some(brain_metadata) = brain_file_metadata(
        connection,
        FixedString::new(ini_file_name.clone()).unwrap(),
        FileVendor::User,
    )
    .await?
    {
        brain_metadata.crc32 != VEX_CRC32.checksum(&ini_data)
    } else {
        true
    };

    if needs_ini_upload {
        let ini_progress = Arc::new(Mutex::new(None));

        connection
            .execute_command(UploadFile {
                filename: FixedString::new(ini_file_name.clone()).unwrap(),
                metadata: FileMetadata {
                    extension: FixedString::new("ini".to_string()).unwrap(),
                    extension_type: ExtensionType::default(),
                    timestamp: j2000_timestamp(),
                    version: Version {
                        major: 1,
                        minor: 0,
                        build: 0,
                        beta: 0,
                    },
                },
                vendor: None,
                data: ini_data,
                target: None,
                load_addr: USER_PROGRAM_LOAD_ADDR,
                linked_file: None,
                after_upload: FileExitAction::DoNothing,
                progress_callback: Some(build_progress_callback(
                    format!("Uploading {}!", ini_file_name.clone()),
                    100,
                    ini_progress.clone(),
                )),
            })
            .await?;
        println!(" 100%");
    }

    let upload_strategy = true;
    match upload_strategy {
        //Future linked runtimes?
        false => {}
        true => {
            let cold = false; // Future cli option?
            let needs_runtime_upload = cold
                || (match brain_file_metadata(
                    connection,
                    FixedString::new(runtime_name.clone()).unwrap(),
                    FileVendor::User,
                )
                .await
                {
                    Ok(Some(result)) => result.metadata.version != runtime_version,
                    _ => true,
                });

            if needs_runtime_upload {
                // indicatif is a little dumb with timestamp handling, so we're going to do this all custom,
                // which unfortunately requires us to juggle timestamps across threads.
                let base_timestamp = Arc::new(Mutex::new(None));

                // if base_data.len() > DIFFERENTIAL_UPLOAD_MAX_SIZE {
                //     return Err(CliError::ProgramTooLarge(base_data.len()));
                // }

                connection
                    .execute_command(UploadFile {
                        filename: FixedString::new(runtime_name.clone()).unwrap(),
                        metadata: FileMetadata {
                            extension: FixedString::new("bin".to_string()).unwrap(),
                            extension_type: ExtensionType::default(),
                            timestamp: j2000_timestamp(),
                            version: runtime_version,
                        },
                        vendor: Some(FileVendor::User),
                        data: {
                            let compress = true; // Future cli option
                            if compress {
                                gzip_compress(&mut runtime);
                            }
                            runtime
                        },
                        target: None,
                        load_addr: USER_PROGRAM_LOAD_ADDR,
                        linked_file: None,
                        after_upload: FileExitAction::DoNothing,
                        progress_callback: Some(build_progress_callback(
                            format!("Uploading {}!", runtime_name.clone()),
                            100,
                            base_timestamp.clone(),
                        )),
                    })
                    .await?;
                println!(" 100%");
            };

            let user_program_timestamp = Arc::new(Mutex::new(None));

            // if runtime.len() > DIFFERENTIAL_UPLOAD_MAX_SIZE {
            //     return Err(CliError::ProgramTooLarge(base.len()));
            // } else if user_program.len() > DIFFERENTIAL_UPLOAD_MAX_SIZE {
            //     return Err(CliError::ProgramTooLarge(new.len()));
            // }

            gzip_compress(&mut user_program);

            let command = UploadFile {
                filename: FixedString::new(slot_file_name.clone()).unwrap(),
                metadata: FileMetadata {
                    extension: FixedString::new("bin".to_string()).unwrap(),
                    extension_type: ExtensionType::default(),
                    timestamp: j2000_timestamp(),
                    version: Version {
                        major: 1,
                        minor: 0,
                        build: 0,
                        beta: 0,
                    },
                },
                vendor: Some(FileVendor::User),
                data: user_program,
                target: None,
                load_addr: PROS_HOT_BIN_LOAD_ADDR,
                linked_file: Some(LinkedFile {
                    filename: FixedString::new(runtime_name.clone()).unwrap(),
                    vendor: Some(FileVendor::User),
                }),
                after_upload: match after {
                    AfterUpload::None => FileExitAction::DoNothing,
                    AfterUpload::ShowScreen => FileExitAction::ShowRunScreen,
                    AfterUpload::Run => FileExitAction::RunProgram,
                },
                progress_callback: Some(build_progress_callback(
                    format!("Uploading {}!", slot_file_name.clone()),
                    100,
                    user_program_timestamp.clone(),
                )),
            };

            connection
                .packet_handshake::<InitFileTransferReplyPacket>(
                    Duration::from_millis(500),
                    15,
                    InitFileTransferPacket::new(InitFileTransferPayload {
                        operation: FileInitAction::Write,
                        target: command.target.unwrap_or(FileTransferTarget::Qspi),
                        vendor: command.vendor.unwrap_or(FileVendor::User),
                        options: FileInitOption::Overwrite,
                        file_size: command.data.len() as u32,
                        load_address: command.load_addr,
                        write_file_crc: VEX_CRC32.checksum(&command.data),
                        metadata: command.metadata.clone(),
                        file_name: command.filename.clone(),
                    }),
                )
                .await?;

            connection.execute_command(command).await?;

            println!(" 100%");
        }
    }

    if after == AfterUpload::Run {
        println!("     \x1b[1;92mRunning\x1b[0m `{}`", slot_file_name);
    }

    Ok(())
}
