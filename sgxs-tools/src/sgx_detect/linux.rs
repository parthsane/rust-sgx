use std::ffi::OsString;
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::process::Command;

use byteorder::{ReadBytesExt, LE};
use failure::{Error, Fail, ResultExt};

use crate::DetectError;

pub fn rdmsr(address: u64) -> Result<u64, Error> {
    fn modprobe_msr() -> Result<(), Error> {
        let output = Command::new("modprobe")
            .arg("msr")
            .output()
            .context("Failed executing modprobe")?;
        match output.status.success() {
            true => Ok(()),
            false => bail!("{}", String::from_utf8_lossy(&output.stderr).trim_end()),
        }
    }

    let mut attempt = 0;
    loop {
        attempt += 1;
        let file = File::open("/dev/cpu/0/msr");
        match file {
            Ok(mut f) => {
                f.seek(SeekFrom::Start(address))
                    .context("Failed to read MSR")?;
                return f
                    .read_u64::<LE>()
                    .context("Failed to read MSR")
                    .map_err(Into::into);
            }
            Err(ref e) if attempt == 1 && e.kind() == ErrorKind::NotFound => {
                modprobe_msr().context("Failed to load MSR kernel module")?;
                continue;
            }
            Err(e) => bail!(e.context("Failed to open MSR device")),
        }
    }
}

pub fn read_efi_var(name: &str, guid: &str) -> Result<Vec<u8>, Error> {
    let fspath = (|| {
        for line in BufReader::new(File::open("/proc/self/mountinfo")?).split(b'\n') {
            let line = line?;
            let mut mountinfo = line.split(|&c| c == b' ');
            if let Some(path) = mountinfo.nth(4) {
                let fs = mountinfo.skip(1).skip_while(|&i| i != b"-").nth(1);
                if fs == Some(b"efivarfs") {
                    return Ok(PathBuf::from(OsString::from_vec(path.into())));
                }
            }
        }
        Err(ErrorKind::NotFound.into())
    })()
    .map_err(|e| Error::from(DetectError::EfiFsError(e)))?;

    (|| {
        let mut file = File::open(fspath.join(&format!("{}-{}", name, guid)))?;
        let mut buf = [0u8; 4];
        file.read_exact(&mut buf)?; // skip EFI attributes
        let mut buf = vec![];
        file.read_to_end(&mut buf)?;
        Ok(buf)
    })()
    .map_err(|e| DetectError::EfiVariableError(e).into())
}
