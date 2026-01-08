// Copyright (c) 2021 Quark Container Authors / 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


pub mod config;
pub mod attester;
pub mod util;
pub mod kbc;

use self::attester::sev::SevAttester;
#[allow(unused_imports)]
use core::convert::TryFrom;
use log::*;
#[allow(unused_imports)]
use alloc::string::{String, ToString};
use alloc::vec::Vec;
#[allow(unused_imports)]
use crate::attestation_client::util::connection::{tls_connection,
    ConnectionClient, Connector};
#[allow(unused_imports)]
use crate::attestation_client::util::ResourceUri;
use crate::qlib::common::{Result, Error};
#[allow(unused_imports)]
use crate::qlib::linux_def::{ATType, Flags};
#[allow(unused_imports)]
use crate::syscalls::sys_file::{close, createAt};
#[allow(unused_imports)]
use crate::syscalls::sys_write::Write;
#[allow(unused_imports)]
use crate::Task;
use crate::{drivers::tee::attestation::{Challenge, Response},
    qlib::{config::CCMode, kernel::arch::tee::{get_tee_type,
        is_hw_tee}}};

#[allow(unused_imports)]
use self::kbc::{kbc_build, Kbc};
#[allow(unused_imports)]
use self::util::{AttestationToken, InitDataStatus};
use self::{attester::Attester, config::AaConfig};
use alloc::boxed::Box;

pub trait AttestationClientTrait {
    fn get_hw_tee_type(&self) -> Option<CCMode> {
        if is_hw_tee() {
            return Some(get_tee_type());
        }
        None
    }

    // Check if data matches host initial data provided during launch of TEE enviroment.
    // Possible Support: TDX, SEV/SNP
    fn check_init_data(&self, _init_data:Vec<u8>) -> Result<InitDataStatus> {
        Ok(InitDataStatus::Unsupported)
    }

    fn get_attestation_token(&mut self, con_client: &mut ConnectionClient)
        -> Result<AttestationToken>;

    // Get measuremnt blob from TEE.
    fn get_tee_evidence(&self, challenge: Vec<u8>) -> Result<Response>;

    // Extend runtime measuremnt register of TEE when available.
    // Possible Support: TDX, SNV/SNP
    fn extend_runtime_measurement(&self) -> Result<bool> {
        Ok(false)
    }
}

#[allow(dead_code)]
pub struct AttestationClient {
    attester: Attester,
    kbc: Kbc,
    config: AaConfig,
}

impl AttestationClient {
    pub fn try_attest(_config_path: Option<String>, _envv: Option<Vec<String>>) {
        // Generate local attestation report to verify TEE environment
        let tee_type = get_tee_type();
        let attester = Self::get_attester(tee_type);
        if attester.is_none() {
            error!("VM: AA - No attester available for TEE type: {:?}", tee_type);
            return;
        }

        
        // Generate attestation report with empty challenge (for self-verification)
        let attester = attester.unwrap();
        let challenge: Challenge = vec![0u8; 64];
        match attester.get_tee_evidence(&mut challenge.clone()) {
            Ok(report) => {
                info!("VM: AA - Successfully generated attestation report ({} bytes)", report.len());
            }
            Err(e) => {
                error!("VM: AA - Failed to generate attestation report: {:?}", e);
            }
        }

        // TODO: KBS-based remote attestation is disabled for now.
        // It should only be enabled when:
        // 1. Running in shim mode (k8s)
        // 2. User specifies secrets in their yaml configuration
        //
        // let mut aa: AttestationClient = Self::new(config_path, envv)
        //     .expect("AA - failed to create instance");
        // let resource_list = aa.get_resource_list();
        // ... KBS connection and resource retrieval ...
    }

    #[allow(dead_code)]
    fn install_resource(list: Vec<(String, Vec<u8>)>) {
        use crate::qlib::linux_def::{ModeType, FileMode};
        use crate::qlib::cstring::CString;
        let task = Task::Current();
        let mode = ModeType::MODE_USER_READ | ModeType::MODE_GROUP_READ
            | ModeType::MODE_USER_WRITE | ModeType::MODE_GROUP_WRITE;
        let flag = Flags::O_CREAT | Flags::O_WRONLY;
        for (_name, _content) in list {
            let fname = CString::New(_name.as_str());
            let addr = fname.Ptr();
            let content = core::str::from_utf8(_content.as_slice())
                .expect("valid utf8 contnet");
            let content = CString::New(content);
            let fd = createAt(task, ATType::AT_FDCWD,
                addr, flag as u32, FileMode(mode)).expect("crate failed");
            if fd > 0i32 {
                let size: i64 = content.Len() as i64;
                let addr = content.Ptr();
                let res = Write(task, fd, addr, size).map_err(|e| {
                    panic!("VM: write content failed:{:?}", e);
                });
                debug!("VM: wrote in file:{:?} bytes", res);
                close(task, fd).expect("VM: failed to close fd");
            } else {
                panic!("VM: AA - failed to create :{:?} on guest", fname.Slice());
            }
        }
    }

    #[allow(dead_code)]
    fn get_resource_list(&self) -> Vec<(String, ResourceUri)> {
        let mut resourse_list: Vec<(String, ResourceUri)> = vec![];
        self.config.kbs_resources()
            .inspect(|list| {
                for item in *list {
                    let i = item.clone();
                    let uri = ResourceUri {
                        kbs_address: self.config.kbs_url(),
                        repository: i.repo,
                        r#type: i.r#type,
                        tag: i.tag,
                        query: i.query,
                    };
                    resourse_list.push((i.local_name, uri));
                }
            });
        resourse_list
    }

    #[allow(dead_code)]
    pub fn new(_config_path: Option<String>, _env: Option<Vec<String>>) -> Result<Self> {
        let _attester = Self::get_attester(get_tee_type());
        if _attester.is_none() {
            return Err(Error::Common(String::from("Attestation not supported")));
        }

        let _config = AaConfig::new(_config_path, _env);
        // Only Background check is supported at the moment.
        let _kbc = kbc_build(kbc::KbsClientType::BckgCheck,
            _config.kbs_url(), _config.kbs_cert());
        Ok(AttestationClient {
            attester: _attester.unwrap(),
            kbc: _kbc,
            config: _config,
        })
    }

    fn get_attester(mode: CCMode) -> Option<Attester> {
        match mode {
            CCMode::Normal | CCMode::NormalEmu
            | CCMode::None => {
                error!("AA: No AA instance for CC mode:{:?}", mode);
                None
            },
            CCMode::SevSnp => Some(Box::new(SevAttester::default())),
        }
    }
}
impl AttestationClientTrait for AttestationClient {
    fn get_attestation_token(&mut self, con_client: &mut ConnectionClient)
        -> Result<AttestationToken> {
        let tee = self.get_hw_tee_type()
            .expect("VM: AA - expected HW TEE backup");
        let tee = String::try_from(tee).unwrap();
        let token = self.kbc.get_token(tee, con_client, &self)
            .expect("VM: AA - failed to get token");
        let _ = self.kbc.update_token(Some(token.clone()));
        Ok(token.inhalt.clone().as_bytes().to_vec())
    }

    fn get_tee_evidence(&self, challenge: Vec<u8>) -> Result<Response> {
        let mut nonce: Challenge = challenge;
        self.attester.get_tee_evidence(&mut nonce)
    }
}