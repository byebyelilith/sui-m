// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use diesel::prelude::*;
use sui_field_count::FieldCount;

use crate::schema::{kv_packages, sum_packages};

#[derive(Insertable, Queryable, Debug, Clone, FieldCount)]
#[diesel(table_name = sum_packages, primary_key(package_id))]
pub struct StoredPackage {
    pub package_id: Vec<u8>,
    pub original_id: Vec<u8>,
    pub package_version: i64,
    pub move_package: Vec<u8>,
    pub cp_sequence_number: i64,
}

#[derive(Insertable, Queryable, Debug, Clone, FieldCount)]
#[diesel(table_name = kv_packages, primary_key(package_id, package_version))]
pub struct StoredKvPackage {
    pub package_id: Vec<u8>,
    pub package_version: i64,
    pub original_id: Vec<u8>,
    pub is_system_package: bool,
    pub serialized_object: Vec<u8>,
    pub cp_sequence_number: i64,
}
