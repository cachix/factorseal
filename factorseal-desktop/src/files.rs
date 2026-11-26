use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

pub(crate) struct ChosenFile(PathBuf);

impl ChosenFile {
    pub(crate) fn name(&self) -> String {
        self.0.display().to_string()
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn path(&self) -> Option<&Path> {
        Some(&self.0)
    }

    pub(crate) async fn read(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let path = self.0.clone();
        smol::unblock(move || factorseal::transfer::read_transfer_file(&path))
            .await
            .map_err(|error| error.to_string())
    }

    pub(crate) async fn write(&self, bytes: Zeroizing<Vec<u8>>) -> Result<(), String> {
        let path = self.0.clone();
        smol::unblock(move || factorseal::transfer::write_private_file(&path, &bytes))
            .await
            .map_err(|error| error.to_string())
    }
}

pub(crate) async fn open(title: &str, label: &str, extension: &str) -> Option<ChosenFile> {
    rfd::AsyncFileDialog::new()
        .set_title(title)
        .add_filter(label, &[extension])
        .pick_file()
        .await
        .map(|file| ChosenFile(file.path().to_owned()))
}

pub(crate) async fn save(
    title: &str,
    label: &str,
    extension: &str,
    name: &str,
) -> Option<ChosenFile> {
    rfd::AsyncFileDialog::new()
        .set_title(title)
        .add_filter(label, &[extension])
        .set_file_name(name)
        .save_file()
        .await
        .map(|file| ChosenFile(file.path().to_owned()))
}
