#![feature(io, page_size, path_ext, collections, convert)]

extern crate uuid;

use std::fs;
use std::fs::PathExt;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::io::{Result, Error, Read, Write};
use std::io::ErrorKind::Other;
use std::string::String;

use std::env;
use uuid::Uuid;

const TARGET_PATH: &'static str = "/sys/kernel/config/target/";
const HBA_PATH: &'static str = "/sys/kernel/config/target/core";

pub fn get_fabrics() -> Result<Vec<Fabric>> {
    let dir = try!(fs::read_dir(TARGET_PATH));

    Ok(dir
       .filter_map(|path| if path.is_ok() {Some(path.unwrap().path())} else {None})
       .filter(|path| path.is_dir())
       .filter(|path| path.file_name().unwrap() != "core")
       .map(|path| Fabric { path: path } )
       .collect()
       )
}

#[derive(Debug, PartialEq, Copy)]
pub enum FabricType {
    ISCSI,
    FCoE,
    Qla2xxx,
    SRP,
    Loopback,
    VHost,
    SBP2,
}

pub struct Fabric {
    path: PathBuf,
}

impl Fabric {

    pub fn new(kind: FabricType) -> Result<Fabric> {
        let dirname = match kind {
            FabricType::ISCSI => "iscsi",
            FabricType::FCoE => "tcm_fc",
            FabricType::Qla2xxx => "qla2xxx",
            FabricType::SRP => "srpt",
            FabricType::Loopback => "loopback",
            FabricType::VHost => "vhost",
            FabricType::SBP2 => "sbp",
        };

        let path = PathBuf::from(TARGET_PATH).join(dirname);
        if !path.exists() {
            try!(fs::create_dir_all(&path))
        }
        Ok(Fabric { path: path } )
    }

    pub fn get_discovery_auth(&self, attr: &str) -> Result<String> {
        get_dir_val(&self.path, "discovery_auth", attr)
    }

    pub fn set_discovery_auth(&self, attr: &str, value: &str) -> Result<()> {
        set_dir_val(&self.path, "discovery_auth", attr, value)
    }

    pub fn get_targets(&self) -> Result<Vec<Target>> {
        let mut targets = Vec::new();
        let fab_paths = try!(fs::read_dir(&self.path));

        for t_path in fab_paths
            .filter_map(|path| if path.is_ok() {Some(path.unwrap().path())} else {None})
            .filter(|path| path.is_dir())
            .filter(|path| path.file_name().unwrap() != "discovery_auth") {
                let tpg_paths = try!(fs::read_dir(&t_path));

                for tpg_path in tpg_paths
                    .filter_map(|path| if path.is_ok() {Some(path.unwrap().path())} else {None})
                    .filter(|p| p.starts_with("tpgt_")) {
                        targets.push(Target { path: tpg_path });
                    }
            }
        Ok(targets)
    }
}

fn get_val(path: &Path, attr: &str) -> Result<String> {
    let attr_path = path.join(attr);
    let mut file = try!(File::open(&attr_path));
    let mut str = String::new();
    try!(file.read_to_string(&mut str));
    Ok(str.trim_right().to_string())
}

fn set_val(path: &Path, attr: &str, value: &str) -> Result<()> {
    let attr_path = path.join(attr);
    let mut file = try!(File::open(&attr_path));
    try!(file.write_all(value.as_bytes()));
    Ok(())
}

//
// Not to be confused with set_val(), this always writes to $path/control,
// but then writes the string "$attr=$value".
// (set_val writes "$value" to $path/$attr.)
//
fn write_control(path: &Path, attr: &str, value: &str) -> Result<()> {
    let output = format!("{}={}", attr, value);
    set_val(path, "control", &output)
}

fn get_dir_val(path: &Path, dir: &str, attr: &str) -> Result<String> {
    get_val(&path.join(dir), attr)
}

fn set_dir_val(path: &Path, dir: &str, attr: &str, value: &str) -> Result<()> {
    set_val(&path.join(dir), attr, value)
}

fn get_bool(path: &Path, attr: &str) -> Result<bool> {
    let str = try!(get_val(path, attr));
    match &str[..] {
        "0" => Ok(false),
        "1" => Ok(true),
	_ => Err(Error::new(Other, "invalid value from configfs",  None))
        }
}

fn set_bool(path: &Path, attr: &str, value: bool) -> Result<()> {
    let val = (value as usize).to_string();
    set_val(path, attr, &val)
}

pub struct Target {
    path: PathBuf,
}

//
// In Lio, a target doesn't actually do much - it's just a container for
// TPGs. Make our Target equivalent to a tpg. This means you can have
// Targets with the same name but different tpg tags.
//
impl Target {

    pub fn new(fabric: &Fabric, name: &str, tpg: u32) -> Result<Target> {
        let path = fabric.path.join(name).join(&format!("tpgt_{}", tpg));
        try!(fs::create_dir_all(&path));
        Ok(Target { path: path } )
    }

    pub fn get_name(&self) -> String {
        let mut my_path = self.path.clone();
        my_path.pop();
        String::from_str(my_path.file_name().unwrap().to_str().unwrap())
    }

    pub fn get_tpg(&self) -> u32 {
        self.path.file_name().unwrap().to_str().unwrap()[5..].parse().unwrap()
    }

    pub fn get_attribute(&self, attr: &str) -> Result<String> {
        get_dir_val(&self.path, "attrib", attr)
    }
    pub fn set_attribute(&self, attr: &str, value: &str) -> Result<()> {
        set_dir_val(&self.path, "attrib", attr, value)
    }

    pub fn get_param(&self, attr: &str) -> Result<String> {
        get_dir_val(&self.path, "param", attr)
    }
    pub fn set_param(&self, attr: &str, value: &str) -> Result<()> {
        set_dir_val(&self.path, "param", attr, value)
    }

    pub fn get_auth(&self, attr: &str) -> Result<String> {
        get_dir_val(&self.path, "auth", attr)
    }
    pub fn set_auth(&self, attr: &str, value: &str) -> Result<()> {
        set_dir_val(&self.path, "auth", attr, value)
    }

    pub fn get_enable(&self) -> Result<bool> {
        get_bool(&self.path, "enable")
    }
    pub fn set_enable(&self, value: bool) -> Result<()> {
        set_bool(&self.path, "enable", value)
    }

    pub fn get_acls(&self) -> Result<Vec<ACL>> {
        let path = self.path.join("acls");
        let paths = try!(fs::read_dir(&path));

        Ok(paths
           .filter_map(|path| if path.is_ok() {Some(path.unwrap().path())} else {None})
           .map(|x| ACL {path: x})
           .collect()
           )
    }

    pub fn get_luns(&self) -> Result<Vec<LUN>> {
        let path = self.path.join("lun");
        let paths = try!(fs::read_dir(&path));

        Ok(paths
           .filter_map(|path| if path.is_ok() {Some(path.unwrap().path())} else {None})
           .map(|x| LUN {path: x})
           .collect()
           )
    }

    pub fn get_portals(&self) -> Result<Vec<Portal>> {
        let path = self.path.join("np");
        let paths = try!(fs::read_dir(&path));

        Ok(paths
           .filter_map(|path| if path.is_ok() {Some(path.unwrap().path())} else {None})
           .map(|x| Portal {path: x})
           .collect()
           )
    }
}

pub struct Portal {
    path: PathBuf,
}

impl Portal {

    pub fn new(target: &Target, ip: &str, port: u16) -> Result<Portal> {
        let path = target.path.join(&format!("{}:{}", ip, port));
        try!(fs::create_dir_all(&path));
        Ok(Portal { path: path } )
    }

    pub fn get_ip(&self) -> String {
        let end_path = self.path.file_name().unwrap().to_str().unwrap();
        let colon_idx = end_path.rfind(':').unwrap();
        end_path[..colon_idx].to_string()
    }

    // TODO: broken for ipv6
    pub fn get_port(&self) -> u16 {
        let end_path = self.path.file_name().unwrap().to_str().unwrap();
        let colon_idx = end_path.rfind(':').unwrap();
        end_path[colon_idx+1..].parse().unwrap()
    }
}

pub struct LUN {
    path: PathBuf,
}

//
// Create a randomly-named link in "to" that points to "from"
//
fn lio_symlink(from: &Path, to: &Path) -> Result<()> {
    let u4 = &Uuid::new_v4().to_simple_string()[..10];
    try!(fs::soft_link(from, &to.join(u4)));
    Ok(())
}

impl LUN {

    pub fn new(target: &Target, so: &StorageObject, lun: u32) -> Result<LUN> {
        // Make the LUN
        let path = target.path.join("lun").join(&format!("lun_{}", lun));
        try!(fs::create_dir_all(&path));

        // Link it to storage object
        try!(lio_symlink(so.get_path(), &path));

        Ok(LUN { path: path } )
    }

    pub fn get_lun(&self) -> u32 {
        let end_path = self.path.file_name().unwrap().to_str().unwrap();
        // chop off "lun_"
        end_path[4..].parse().unwrap()
    }
}

pub struct ACL {
    path: PathBuf,
}

impl ACL {

    pub fn new(target: &Target, acl: &str) -> Result<ACL> {
        let path = target.path.join(acl);
        try!(fs::create_dir_all(&path));
        Ok(ACL { path: path } )
    }

    pub fn get_attribute(&self, attr: &str) -> Result<String> {
        get_dir_val(&self.path, "attrib", attr)
    }
    pub fn set_attribute(&self, attr: &str, value: &str) -> Result<()> {
        set_dir_val(&self.path, "attrib", attr, value)
    }

    pub fn get_param(&self, attr: &str) -> Result<String> {
        get_dir_val(&self.path, "param", attr)
    }
    pub fn set_param(&self, attr: &str, value: &str) -> Result<()> {
        set_dir_val(&self.path, "param", attr, value)
    }

    pub fn get_mapped_luns(&self) -> Result<Vec<MappedLUN>> {
        let paths = try!(fs::read_dir(&self.path));

        Ok(paths
            .filter_map(|path| if path.is_ok() {Some(path.unwrap().path())} else {None})
            .filter(|p| p.starts_with("lun_"))
            .map(|x| MappedLUN {path: x})
            .collect()
           )
    }
}

pub struct MappedLUN {
    path: PathBuf,
}

impl MappedLUN {

    pub fn new(acl: &ACL, tpg_lun: &LUN, lun: u32) -> Result<MappedLUN> {
        let path = acl.path.join(&format!("lun_{}", lun.to_string()));

        try!(fs::create_dir_all(&path));

        // Link it to storage object
        try!(lio_symlink(&tpg_lun.path, &path));

        Ok(MappedLUN { path: path })
    }

    pub fn get_write_protect(&self) -> Result<bool> {
        get_bool(&self.path, "write_protect")
    }

    pub fn set_write_protect(&self, value: bool) -> Result<()> {
        set_bool(&self.path, "write_protect", value)
    }
}

#[derive(Debug, PartialEq, Copy)]
pub enum StorageObjectType {
    Block,
    Fileio,
    Ramdisk,
    ScsiPass,
    UserPass,
}

pub trait StorageObject {
    fn get_path(&self) -> &Path;
    fn get_type(&self) -> StorageObjectType;

    fn get_attribute(&self, attr: &str) -> Result<String> {
        get_dir_val(&self.get_path(), "attrib", attr)
    }

    fn set_attribute(&self, attr: &str, value: &str) -> Result<()> {
        set_dir_val(self.get_path(), "attrib", attr, value)
    }

    fn get_pr(&self, attr: &str) -> Result<String> {
        get_dir_val(&self.get_path(), "pr", attr)
    }

    fn set_pr(&self, attr: &str, value: &str) -> Result<()> {
        set_dir_val(&self.get_path(), "pr", attr, value)
    }

    fn get_wwn(&self, attr: &str) -> Result<String> {
        get_dir_val(&self.get_path(), "wwn", attr)
    }

    fn set_wwn(&self, attr: &str, value: &str) -> Result<()> {
        set_dir_val(&self.get_path(), "wwn", attr, value)
    }
}

pub struct BlockStorageObject {
    path: PathBuf,
}

// TODO: err out if (type, name) already exists?
fn get_free_hba_path(kind: StorageObjectType, name: &str) -> Result<PathBuf> {
    let paths = try!(fs::read_dir(HBA_PATH));

    let max: Option<u32> = paths
        .filter_map(|path| if path.is_ok() {Some(path.unwrap().path())} else {None})
        .filter(|p| p.starts_with(get_hba_prefix(kind)))
        .map(|p| {
            let idx = p.to_str().unwrap().rfind('_').unwrap();
            p.to_str().unwrap()[idx+1..].parse().unwrap()
        })
        .max();

    let new_val = match max {
        Some(x) => x + 1,
        None => 0
    };

    let hba_name = format!("{}_{}", get_hba_prefix(kind), new_val);

    Ok(PathBuf::from(HBA_PATH).join(&hba_name).join(name))
}

impl BlockStorageObject {
    pub fn new(name: &str, backing_dev: &str) -> Result<BlockStorageObject> {
        let path = try!(get_free_hba_path(StorageObjectType::Block, name));

        try!(fs::create_dir_all(&path));
        try!(write_control(&path, "udev_path", backing_dev));
        try!(set_val(&path, "enable", "1"));

        Ok(BlockStorageObject{ path: path })
    }
}

impl StorageObject for BlockStorageObject {
    fn get_path(&self) -> &Path {
        &self.path
    }

    fn get_type(&self) -> StorageObjectType { StorageObjectType::Block }
}

pub struct FileioStorageObject {
    path: PathBuf,
}

impl FileioStorageObject {
    pub fn new(name: &str, backing_file: &str, write_back: bool) -> Result<FileioStorageObject> {
        let path = try!(get_free_hba_path(StorageObjectType::Fileio, name));

        try!(fs::create_dir_all(&path));

        // backing file must exist
        if path.is_file() {
            try!(write_control(&path, "fd_dev_name", backing_file));
            let size = try!(fs::metadata(&path)).len();
            try!(write_control(&path, "fd_dev_size", &size.to_string()));
        }

        if write_back {
            try!(set_dir_val(&path, "attrib", "emulate_write_cache", "1"));
            try!(write_control(&path, "fd_buffered_io", "1"));
        }

        try!(set_val(&path, "udev_path", backing_file));
        try!(set_val(&path, "enable", "1"));

        Ok(FileioStorageObject{ path: path })
    }
}

impl StorageObject for FileioStorageObject {
    fn get_path(&self) -> &Path {
        &self.path
    }

    fn get_type(&self) -> StorageObjectType { StorageObjectType::Fileio }
}

pub struct RamdiskStorageObject {
    path: PathBuf,
}

impl RamdiskStorageObject {
    pub fn new(name: &str, size: u64) -> Result<RamdiskStorageObject> {
        let path = try!(get_free_hba_path(StorageObjectType::Ramdisk, name));

        try!(fs::create_dir_all(&path));

        let pages = size / env::page_size() as u64;

        try!(set_val(&path, "rd_pages", &pages.to_string()));
        try!(set_val(&path, "enable", "1"));

        Ok(RamdiskStorageObject{ path: path })
    }
}

impl StorageObject for RamdiskStorageObject {
    fn get_path(&self) -> &Path {
        &self.path
    }

    fn get_type(&self) -> StorageObjectType { StorageObjectType::Ramdisk }
}

pub struct ScsiPassStorageObject {
    path: PathBuf,
}

fn get_hctl_for_dev(dev: &str) -> Result<(u8, u8, u8, u32)> {
    let mut path = PathBuf::from("/sys/block");
    path.push(dev);
    path.push("device");
    path.push("scsi_device");

    let mut paths = try!(fs::read_dir(&path));
    let first_path = paths.next();
    let hctl_parts: Vec<u32> = first_path.unwrap().unwrap().path().file_name().unwrap().to_str().unwrap()
        .split(':')
        .map(|x| x.parse().unwrap())
        .collect();

    Ok((hctl_parts[0] as u8, hctl_parts[1] as u8, hctl_parts[2] as u8, hctl_parts[3]))
}

impl ScsiPassStorageObject {
    pub fn new(name: &str, backing_dev: &str) -> Result<ScsiPassStorageObject> {
        let path = try!(get_free_hba_path(StorageObjectType::ScsiPass, name));

        let (h, c, t, l) = try!(get_hctl_for_dev(backing_dev));

        try!(fs::create_dir_all(&path));

        try!(write_control(&path, "scsi_host_id", &h.to_string()));
        try!(write_control(&path, "scsi_channel_id", &c.to_string()));
        try!(write_control(&path, "scsi_target_id", &t.to_string()));
        try!(write_control(&path, "scsi_lun_id", &l.to_string()));

        try!(set_val(&path, "udev_path", &format!("/dev/{}", &backing_dev)));
        try!(set_val(&path, "enable", "1"));

        Ok(ScsiPassStorageObject{ path: path })
    }
}

impl StorageObject for ScsiPassStorageObject {
    fn get_path(&self) -> &Path {
        &self.path
    }

    fn get_type(&self) -> StorageObjectType { StorageObjectType::ScsiPass }
}

pub struct UserPassStorageObject {
    path: PathBuf,
}

#[derive(Debug, PartialEq, Copy)]
pub enum PassLevel {
    PassAll,
    PassIO,
}

impl UserPassStorageObject {
    pub fn new(name: &str, size: u64, pass_level: PassLevel, config: &str) -> Result<UserPassStorageObject> {
        let path = try!(get_free_hba_path(StorageObjectType::UserPass, name));
        try!(fs::create_dir_all(&path));

        try!(write_control(&path, "dev_config", config));
        try!(write_control(&path, "pass_level", &(pass_level as u8).to_string()));
        try!(write_control(&path, "dev_size", &size.to_string()));

        try!(set_val(&path, "enable", "1"));

        Ok(UserPassStorageObject{ path: path })
    }
}

impl StorageObject for UserPassStorageObject {
    fn get_path(&self) -> &Path {
        &self.path
    }

    fn get_type(&self) -> StorageObjectType { StorageObjectType::UserPass }
}

fn get_hba_prefix(kind: StorageObjectType) -> &'static str {
    match kind {
        StorageObjectType::Block => "iblock",
        StorageObjectType::Fileio => "fileio",
        StorageObjectType::Ramdisk => "rd_mcp",
        StorageObjectType::ScsiPass => "pscsi",
        StorageObjectType::UserPass => "user",
    }
}

fn get_hba_type(path: &PathBuf) -> Option<StorageObjectType> {
    let end_path = path.file_name().unwrap().to_str().unwrap();
    let idx = end_path.rfind('_').unwrap();
    match &end_path[..idx] {
        "iblock" => Some(StorageObjectType::Block),
        "fileio" => Some(StorageObjectType::Fileio),
        "rd_mcp" => Some(StorageObjectType::Ramdisk),
        "pscsi" => Some(StorageObjectType::ScsiPass),
        "user" => Some(StorageObjectType::UserPass),
        _ => None
    }
}

pub fn get_storage_objects() -> Result<Vec<Box<StorageObject + 'static>>> {
    let hba_paths = try!(fs::read_dir(HBA_PATH));
    let mut sos: Vec<Box<StorageObject>> = Vec::new();

    for hba_path in hba_paths
        .filter_map(|path| if path.is_ok() {Some(path.unwrap().path())} else {None})
        .filter(|p| p.is_dir())
        .filter(|p| p.file_name().unwrap() != "alua") {

            if let Ok(so_paths) = fs::read_dir(&hba_path) {
                for so_path in so_paths
                    .filter_map(|path| if path.is_ok() {Some(path.unwrap().path())} else {None})
                    .filter(|path| path.is_dir()) {
                        match get_hba_type(&so_path) {
                            Some(StorageObjectType::Block) => {
                                sos.push(Box::new(BlockStorageObject { path: so_path }))
                            },
                            Some(StorageObjectType::Fileio) => {
                                sos.push(Box::new(FileioStorageObject { path: so_path }))
                            },
                            Some(StorageObjectType::Ramdisk) => {
                                sos.push(Box::new(RamdiskStorageObject { path: so_path }))
                            },
                            Some(StorageObjectType::ScsiPass) => {
                                sos.push(Box::new(ScsiPassStorageObject { path: so_path }))
                            },
                            Some(StorageObjectType::UserPass) => {
                                sos.push(Box::new(UserPassStorageObject { path: so_path }))
                            },
                            None => { },
                        }
                    }
                }
            }
    Ok(sos)
}


#[test]
fn it_works() {
}
