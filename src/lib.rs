extern crate uuid;

use std::path::Path;
use std::io::fs::PathExtensions;
use std::io::{File, Open, Write, Read, USER_DIR};
use std::io::fs;
use std::io::IoResult;
use std::vec::Vec;
use std::os;
use uuid::Uuid;

static TARGET_PATH: &'static str = "/sys/kernel/config/target/";
static HBA_PATH: &'static str = "/sys/kernel/config/target/core";

pub fn get_fabrics() -> Vec<Fabric> {
    let paths = fs::readdir(&Path::new(TARGET_PATH)).unwrap();

    paths.into_iter()
        .filter(|p| p.is_dir() && p.filename_str().unwrap() != "core")
        .map(|p| Fabric { path: p } )
        .collect()
}

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
    path: Path,
}

impl Fabric {

    pub fn new(kind: FabricType) -> IoResult<Fabric> {
        let dirname = match kind {
            ISCSI => "iscsi",
            FCoE => "tcm_fc",
            Qla2xxx => "qla2xxx",
            SRP => "srpt",
            Loopback => "loopback",
            VHost => "vhost",
            SBP2 => "sbp",
        };

        let path = Path::new(TARGET_PATH).join(dirname);
        try!(maybe_make_path(&path));
        Ok(Fabric { path: path } )
    }

    pub fn get_discovery_auth(&self, attr: &str) -> IoResult<String> {
        get_dir_val(&self.path, "discovery_auth", attr)
    }

    pub fn set_discovery_auth(&self, attr: &str, value: &str) -> IoResult<()> {
        set_dir_val(&self.path, "discovery_auth", attr, value)
    }

    pub fn get_targets(&self) -> Vec<Target> {
        let mut targets = Vec::new();
        let fab_paths = fs::readdir(&Path::new(&self.path)).unwrap();

        for t_path in fab_paths.into_iter()
            .filter(|p| p.is_dir() && p.filename_str().unwrap() != "discovery_auth") {
            let tpg_paths = fs::readdir(&Path::new(&t_path)).unwrap();

            for tpg_path in tpg_paths.into_iter()
                .filter(|p| p.filename_str().unwrap().starts_with("tpgt_")) {
                targets.push(Target { path: tpg_path });
            }
        }
        targets
    }
}

fn make_path(path: &Path) -> IoResult<()> {
    fs::mkdir_recursive(path, USER_DIR)
}

fn maybe_make_path (path: &Path) -> IoResult<()> {
    match path.stat() {
        Ok(_) => Ok(()),
        Err(_) => { fs::mkdir_recursive(path, USER_DIR) }
    }
}

fn get_val(path: &Path, attr: &str) -> IoResult<String> {
    let attr_path = Path::new(path).join(attr);
    let mut file = try!(File::open_mode(&attr_path, Open, Read));
    let str = try!(file.read_to_string());
    Ok(str.as_slice().trim_right_chars('\n').to_string())
}

fn set_val(path: &Path, attr: &str, value: &str) -> IoResult<()> {
    let attr_path = path.join(attr);
    let mut file = try!(File::open_mode(&attr_path, Open, Write));
    try!(file.write_str(value));
    Ok(())
}

//
// Not to be confused with set_val(), this always writes to $path/control,
// but then writes the string "$attr=$value".
// (set_val writes "$value" to $path/$attr.)
//
fn write_control(path: &Path, attr: &str, value: &str) -> IoResult<()> {
    let output = format!("{}={}", attr, value);
    set_val(path, "control", output.as_slice())
}

fn get_dir_val(path: &Path, dir: &str, attr: &str) -> IoResult<String> {
    let dir_path = Path::new(path).join(dir);
    get_val(&dir_path, attr)
}

fn set_dir_val(path: &Path, dir: &str, attr: &str, value: &str) -> IoResult<()> {
    let dir_path = Path::new(path).join(dir);
    set_val(&dir_path, attr, value)
}

fn get_bool(path: &Path, attr: &str) -> IoResult<bool> {
    let str = try!(get_val(path, attr));
    Ok(from_str(str.as_slice()).unwrap())
}

fn set_bool(path: &Path, attr: &str, value: bool) -> IoResult<()> {
    let str = (value as uint).to_string();
    set_val(path, attr, str.as_slice())
}

pub struct Target {
    path: Path,
}

//
// In Lio, a target doesn't actually do much - it's just a container for
// TPGs. Make our Target equivalent to a tpg. This means you can have
// Targets with the same name but different tpg tags.
//
impl Target {

    pub fn new(fabric: &Fabric, name: &str, tpg: uint) -> IoResult<Target> {
        let path = fabric.path.join(name).join(format!("tpgt_{}", tpg));
        try!(make_path(&path));
        Ok(Target { path: path } )
    }

    pub fn get_name(&self) -> String {
        let mut my_path = self.path.clone();
        my_path.pop();
        my_path.filename_str().unwrap().to_string()
    }

    pub fn get_tpg(&self) -> uint {
        from_str(self.path.filename_str().unwrap().slice_from(5)).unwrap()
    }

    pub fn get_attribute(&self, attr: &str) -> IoResult<String> {
        get_dir_val(&self.path, "attrib", attr)
    }
    pub fn set_attribute(&self, attr: &str, value: &str) -> IoResult<()> {
        set_dir_val(&self.path, "attrib", attr, value)
    }

    pub fn get_param(&self, attr: &str) -> IoResult<String> {
        get_dir_val(&self.path, "param", attr)
    }
    pub fn set_param(&self, attr: &str, value: &str) -> IoResult<()> {
        set_dir_val(&self.path, "param", attr, value)
    }

    pub fn get_auth(&self, attr: &str) -> IoResult<String> {
        get_dir_val(&self.path, "auth", attr)
    }
    pub fn set_auth(&self, attr: &str, value: &str) -> IoResult<()> {
        set_dir_val(&self.path, "auth", attr, value)
    }

    pub fn get_enable(&self) -> IoResult<bool> {
        get_bool(&self.path, "enable")
    }
    pub fn set_enable(&self, value: bool) -> IoResult<()> {
        set_bool(&self.path, "enable", value)
    }

    pub fn get_acls(&self) -> Vec<ACL> {
        let path = self.path.clone().join("acls");
        let paths = fs::readdir(&Path::new(path)).unwrap();

        paths.into_iter().map(|x| ACL {path: x}).collect()
    }

    pub fn get_luns(&self) -> Vec<LUN> {
        let path = self.path.clone().join("lun");
        let paths = fs::readdir(&Path::new(path)).unwrap();

        paths.into_iter().map(|x| LUN {path: x}).collect()
    }

    pub fn get_portals(&self) -> Vec<Portal> {
        let path = self.path.clone().join("np");
        let paths = fs::readdir(&Path::new(path)).unwrap();

        paths.into_iter().map(|x| Portal {path: x}).collect()
    }
}

pub struct Portal {
    path: Path,
}

impl Portal {

    pub fn new(target: &Target, ip: &str, port: uint) -> IoResult<Portal> {
        let path = target.path.join(format!("{}:{}", ip, port));
        try!(make_path(&path));
        Ok(Portal { path: path } )
    }

    pub fn get_ip(&self) -> String {
        let end_path = self.path.filename_str().unwrap();
        let colon_idx = end_path.rfind(':').unwrap();
        end_path.slice_to(colon_idx).to_string()
    }

    // TODO: broken for ipv6
    pub fn get_port(&self) -> uint {
        let end_path = self.path.filename_str().unwrap();
        let colon_idx = end_path.rfind(':').unwrap();
        from_str(end_path.slice_from(colon_idx+1)).unwrap()
    }
}

pub struct LUN {
    path: Path,
}

//
// Create a randomly-named link in "to" that points to "from"
//
fn lio_symlink(from: &Path, to: &Path) -> IoResult<()> {
    let u4 = Uuid::new_v4().to_simple_string().as_slice().slice_to(10).to_string();
    try!(fs::symlink(from, &to.join(u4)));
    Ok(())
}

impl LUN {

    pub fn new(target: &Target, so: &StorageObject, lun: uint) -> IoResult<LUN> {
        let end_part = format!("lun_{}", lun);

        // Make the LUN
        let path = target.path.join("lun").join(end_part);
        try!(make_path(&path));

        // Link it to storage object
        try!(lio_symlink(&so.get_path(), &path));

        Ok(LUN { path: path } )
    }

    pub fn get_lun(&self) -> uint {
        let end_path = self.path.filename_str().unwrap();
        // chop off "lun_"
        from_str(end_path.slice_from(4)).unwrap()
    }
}

pub struct ACL {
    path: Path,
}

impl ACL {

    pub fn new(target: &Target, acl: &str) -> IoResult<ACL> {
        let path = target.path.join(acl);
        try!(make_path(&path));
        Ok(ACL { path: path } )
    }

    pub fn get_attribute(&self, attr: &str) -> IoResult<String> {
        get_dir_val(&self.path, "attrib", attr)
    }
    pub fn set_attribute(&self, attr: &str, value: &str) -> IoResult<()> {
        set_dir_val(&self.path, "attrib", attr, value)
    }

    pub fn get_param(&self, attr: &str) -> IoResult<String> {
        get_dir_val(&self.path, "param", attr)
    }
    pub fn set_param(&self, attr: &str, value: &str) -> IoResult<()> {
        set_dir_val(&self.path, "param", attr, value)
    }

    pub fn get_mapped_luns(&self) -> Vec<MappedLUN> {
        let paths = fs::readdir(&self.path).unwrap();

        paths.into_iter()
            .filter(|p| p.filename_str().unwrap().starts_with("lun_"))
            .map(|x| MappedLUN {path: x})
            .collect()
    }
}

pub struct MappedLUN {
    path: Path,
}

impl MappedLUN {

    pub fn new(acl: &ACL, tpg_lun: &LUN, lun: uint) -> IoResult<MappedLUN> {
        let path = acl.path.join(format!("lun_{}", lun.to_string()));

        try!(make_path(&path));

        // Link it to storage object
        try!(lio_symlink(&tpg_lun.path, &path));

        Ok(MappedLUN { path: path })
    }

    pub fn get_write_protect(&self) -> IoResult<bool> {
        get_bool(&self.path, "write_protect")
    }

    pub fn set_write_protect(&self, value: bool) -> IoResult<()> {
        set_bool(&self.path, "write_protect", value)
    }
}

pub enum StorageObjectType {
    Block,
    Fileio,
    Ramdisk,
    ScsiPass,
    UserPass,
}

pub trait StorageObject {
    fn get_path(&self) -> Path;
    fn get_type(&self) -> StorageObjectType;

    fn get_attribute(&self, attr: &str) -> IoResult<String> {
        get_dir_val(&self.get_path(), "attrib", attr)
    }

    fn set_attribute(&self, attr: &str, value: &str) -> IoResult<()> {
        set_dir_val(&self.get_path(), "attrib", attr, value)
    }

    fn get_pr(&self, attr: &str) -> IoResult<String> {
        get_dir_val(&self.get_path(), "pr", attr)
    }

    fn set_pr(&self, attr: &str, value: &str) -> IoResult<()> {
        set_dir_val(&self.get_path(), "pr", attr, value)
    }

    fn get_wwn(&self, attr: &str) -> IoResult<String> {
        get_dir_val(&self.get_path(), "wwn", attr)
    }

    fn set_wwn(&self, attr: &str, value: &str) -> IoResult<()> {
        set_dir_val(&self.get_path(), "wwn", attr, value)
    }
}

pub struct BlockStorageObject {
    path: Path,
}

// TODO: err out if (type, name) already exists?
fn get_free_hba_path(kind: StorageObjectType, name: &str) -> Path {
    let paths = fs::readdir(&Path::new(HBA_PATH)).unwrap();

    let max = paths.into_iter()
        .filter(|p| p.filename_str().unwrap().starts_with(get_hba_prefix(kind)))
        .map(|p| {
            let idx = p.filename_str().unwrap().rfind('_').unwrap();
            from_str::<uint>(p.filename_str().unwrap().slice_from(idx+1)).unwrap()
        })
        .max();

    let new_val = match max {
        Some(x) => x + 1,
        None => 0
    };

    let hba_name = format!("{}_{}", get_hba_prefix(kind), new_val);

    Path::new(HBA_PATH).join(hba_name).join(name)
}

impl BlockStorageObject {
    pub fn new(name: &str, backing_dev: &str) -> IoResult<BlockStorageObject> {
        let path = get_free_hba_path(Block, name);

        try!(make_path(&path));
        try!(write_control(&path, "udev_path", backing_dev));
        try!(set_val(&path, "enable", "1"));

        Ok(BlockStorageObject{ path: path })
    }
}

impl StorageObject for BlockStorageObject {
    fn get_path(&self) -> Path {
        self.path.clone()
    }

    fn get_type(&self) -> StorageObjectType { Block }
}

pub struct FileioStorageObject {
    path: Path,
}

impl FileioStorageObject {
    pub fn new(name: &str, backing_file: &str, write_back: bool) -> IoResult<FileioStorageObject> {
        let path = get_free_hba_path(Fileio, name);

        try!(make_path(&path));

        // backing file must exist
        if path.is_file() {
            try!(write_control(&path, "fd_dev_name", backing_file));
            let size = try!(path.stat()).size;
            try!(write_control(&path, "fd_dev_size", size.to_string().as_slice()));
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
    fn get_path(&self) -> Path {
        self.path.clone()
    }

    fn get_type(&self) -> StorageObjectType { Fileio }
}

pub struct RamdiskStorageObject {
    path: Path,
}

impl RamdiskStorageObject {
    pub fn new(name: &str, size: u64) -> IoResult<RamdiskStorageObject> {
        let path = get_free_hba_path(Ramdisk, name);

        try!(make_path(&path));

        let pages = size / os::page_size() as u64;

        try!(set_val(&path, "rd_pages", pages.to_string().as_slice()));
        try!(set_val(&path, "enable", "1"));

        Ok(RamdiskStorageObject{ path: path })
    }
}

impl StorageObject for RamdiskStorageObject {
    fn get_path(&self) -> Path {
        self.path.clone()
    }

    fn get_type(&self) -> StorageObjectType { Ramdisk }
}

pub struct ScsiPassStorageObject {
    path: Path,
}

fn get_hctl_for_dev(dev: &str) -> IoResult<(uint, uint, uint, uint)> {
    let path = Path::new("/sys/block");
    path.join_many(&[dev, "device", "scsi_device"]);

    let paths = try!(fs::readdir(&path));
    let hctl_parts: Vec<uint> = paths[0].filename_str().unwrap()
        .split(':')
        .map(|x| from_str(x).unwrap())
        .collect();

    Ok((hctl_parts[0], hctl_parts[1], hctl_parts[2], hctl_parts[3]))
}

impl ScsiPassStorageObject {
    pub fn new(name: &str, backing_dev: &str) -> IoResult<ScsiPassStorageObject> {
        let path = get_free_hba_path(ScsiPass, name);

        let (h, c, t, l) = try!(get_hctl_for_dev(backing_dev));

        try!(make_path(&path));

        try!(write_control(&path, "scsi_host_id", h.to_string().as_slice()));
        try!(write_control(&path, "scsi_channel_id", c.to_string().as_slice()));
        try!(write_control(&path, "scsi_target_id", t.to_string().as_slice()));
        try!(write_control(&path, "scsi_lun_id", l.to_string().as_slice()));

        try!(set_val(&path, "udev_path", format!("/dev/{}", backing_dev).as_slice()));
        try!(set_val(&path, "enable", "1"));

        Ok(ScsiPassStorageObject{ path: path })
    }
}

impl StorageObject for ScsiPassStorageObject {
    fn get_path(&self) -> Path {
        self.path.clone()
    }

    fn get_type(&self) -> StorageObjectType { ScsiPass }
}

pub struct UserPassStorageObject {
    path: Path,
}

pub enum PassLevel {
    PassAll,
    PassIO,
}

impl UserPassStorageObject {
    pub fn new(name: &str, size: u64, pass_level: PassLevel, config: &str) -> IoResult<UserPassStorageObject> {
        let path = get_free_hba_path(UserPass, name);
        try!(make_path(&path));

        try!(write_control(&path, "dev_config", config));
        try!(write_control(&path, "pass_level", (pass_level as uint).to_string().as_slice()));
        try!(write_control(&path, "dev_size", size.to_string().as_slice()));

        try!(set_val(&path, "enable", "1"));

        Ok(UserPassStorageObject{ path: path })
    }
}

impl StorageObject for UserPassStorageObject {
    fn get_path(&self) -> Path {
        self.path.clone()
    }

    fn get_type(&self) -> StorageObjectType { UserPass }
}

fn get_hba_prefix(kind: StorageObjectType) -> &'static str {
    match kind {
        Block => "iblock",
        Fileio => "fileio",
        Ramdisk => "rd_mcp",
        ScsiPass => "pscsi",
        UserPass => "user",
    }
}

fn get_hba_type(path: &Path) -> Option<StorageObjectType> {
    let end_path = path.filename_str().unwrap();
    let idx = end_path.rfind('_').unwrap();
    match end_path.slice_to(idx) {
        "iblock" => Some(Block),
        "fileio" => Some(Fileio),
        "rd_mcp" => Some(Ramdisk),
        "pscsi" => Some(ScsiPass),
        "user" => Some(UserPass),
        _ => None
    }
}

pub fn get_storage_objects() -> Vec<Box<StorageObject + 'static>> {
    let hba_paths = fs::readdir(&Path::new(HBA_PATH)).unwrap();

    let mut sos: Vec<Box<StorageObject>> = Vec::new();

    for path in hba_paths.into_iter()
        .filter(|p| p.is_dir() && p.filename_str().unwrap() != "alua") {
        let so_paths = fs::readdir(&Path::new(&path)).unwrap();

        for so_path in so_paths.into_iter()
            .filter(|p| p.is_dir()) {
            match get_hba_type(&path) {
                Some(Block) => { sos.push(box BlockStorageObject { path: so_path }) },
                Some(Fileio) => { sos.push(box FileioStorageObject { path: so_path }) },
                Some(Ramdisk) => { sos.push(box RamdiskStorageObject { path: so_path }) },
                Some(ScsiPass) => { sos.push(box ScsiPassStorageObject { path: so_path }) },
                Some(UserPass) => { sos.push(box UserPassStorageObject { path: so_path }) },
                None => { },
            }
        }
    }
    sos
}

#[test]
fn it_works() {
}
