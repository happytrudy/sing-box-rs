use std::{
    collections::HashSet,
    io::{Cursor, Read},
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::{Context, Result};
use flate2::read::ZlibDecoder;

use crate::config::{HeadlessRuleConfig, Listable, RuleSetSource};

const MAGIC: &[u8; 3] = b"SRS";
const CURRENT_VERSION: u8 = 5;
const MAX_DECOMPRESSED_SIZE: u64 = 128 * 1024 * 1024;
const MAX_COLLECTION_SIZE: u64 = 4_000_000;
const MAX_RECURSION: usize = 64;

const ITEM_QUERY_TYPE: u8 = 0;
const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
const ITEM_DOMAIN_KEYWORD: u8 = 3;
const ITEM_DOMAIN_REGEX: u8 = 4;
const ITEM_SOURCE_IP_CIDR: u8 = 5;
const ITEM_IP_CIDR: u8 = 6;
const ITEM_SOURCE_PORT: u8 = 7;
const ITEM_SOURCE_PORT_RANGE: u8 = 8;
const ITEM_PORT: u8 = 9;
const ITEM_PORT_RANGE: u8 = 10;
const ITEM_PROCESS_NAME: u8 = 11;
const ITEM_PROCESS_PATH: u8 = 12;
const ITEM_PACKAGE_NAME: u8 = 13;
const ITEM_WIFI_SSID: u8 = 14;
const ITEM_WIFI_BSSID: u8 = 15;
const ITEM_ADGUARD_DOMAIN: u8 = 16;
const ITEM_PROCESS_PATH_REGEX: u8 = 17;
const ITEM_NETWORK_TYPE: u8 = 18;
const ITEM_NETWORK_IS_EXPENSIVE: u8 = 19;
const ITEM_NETWORK_IS_CONSTRAINED: u8 = 20;
const ITEM_NETWORK_INTERFACE_ADDRESS: u8 = 21;
const ITEM_DEFAULT_INTERFACE_ADDRESS: u8 = 22;
const ITEM_PACKAGE_NAME_REGEX: u8 = 23;
const ITEM_FINAL: u8 = 0xff;

pub(crate) fn decode(input: &[u8]) -> Result<RuleSetSource> {
    anyhow::ensure!(input.len() >= 4, "truncated sing-box rule-set header");
    anyhow::ensure!(&input[..3] == MAGIC, "invalid sing-box rule-set magic");
    let version = input[3];
    anyhow::ensure!(
        (1..=CURRENT_VERSION).contains(&version),
        "unsupported rule-set version: {version}"
    );

    let mut decompressed = Vec::new();
    ZlibDecoder::new(&input[4..])
        .take(MAX_DECOMPRESSED_SIZE + 1)
        .read_to_end(&mut decompressed)
        .context("decompress sing-box rule-set")?;
    anyhow::ensure!(
        decompressed.len() as u64 <= MAX_DECOMPRESSED_SIZE,
        "sing-box rule-set exceeds decompressed size limit"
    );

    let mut reader = BinaryReader::new(&decompressed);
    let rule_count = reader.read_count("rule count")?;
    let mut rules = Vec::with_capacity(rule_count);
    for index in 0..rule_count {
        rules.push(
            read_rule(&mut reader, 0).with_context(|| format!("decode binary rule {index}"))?,
        );
    }
    anyhow::ensure!(reader.is_empty(), "trailing data in sing-box rule-set");
    Ok(RuleSetSource { version, rules })
}

fn read_rule(reader: &mut BinaryReader<'_>, depth: usize) -> Result<HeadlessRuleConfig> {
    anyhow::ensure!(depth < MAX_RECURSION, "logical rule nesting is too deep");
    match reader.read_u8()? {
        0 => read_default_rule(reader),
        1 => read_logical_rule(reader, depth + 1),
        kind => anyhow::bail!("unknown binary rule type: {kind}"),
    }
}

fn read_default_rule(reader: &mut BinaryReader<'_>) -> Result<HeadlessRuleConfig> {
    let mut rule = HeadlessRuleConfig::default();
    loop {
        let item = reader.read_u8()?;
        match item {
            ITEM_NETWORK => rule.network = Listable(reader.read_strings()?),
            ITEM_DOMAIN => {
                let (domain, suffix) = read_domain_matcher(reader)?;
                rule.domain = Listable(domain);
                rule.domain_suffix = Listable(suffix);
            }
            ITEM_DOMAIN_KEYWORD => rule.domain_keyword = Listable(reader.read_strings()?),
            ITEM_SOURCE_IP_CIDR => rule.source_ip_cidr = Listable(read_ip_set(reader)?),
            ITEM_IP_CIDR => rule.ip_cidr = Listable(read_ip_set(reader)?),
            ITEM_SOURCE_PORT => rule.source_port = Listable(reader.read_u16s()?),
            ITEM_SOURCE_PORT_RANGE => rule.source_port_range = Listable(reader.read_strings()?),
            ITEM_PORT => rule.port = Listable(reader.read_u16s()?),
            ITEM_PORT_RANGE => rule.port_range = Listable(reader.read_strings()?),
            ITEM_FINAL => {
                rule.invert = reader.read_bool()?;
                return Ok(rule);
            }
            ITEM_QUERY_TYPE => unsupported(reader.read_u16s(), "query_type")?,
            ITEM_DOMAIN_REGEX => unsupported(reader.read_strings(), "domain_regex")?,
            ITEM_PROCESS_NAME => unsupported(reader.read_strings(), "process_name")?,
            ITEM_PROCESS_PATH => unsupported(reader.read_strings(), "process_path")?,
            ITEM_PACKAGE_NAME => unsupported(reader.read_strings(), "package_name")?,
            ITEM_WIFI_SSID => unsupported(reader.read_strings(), "wifi_ssid")?,
            ITEM_WIFI_BSSID => unsupported(reader.read_strings(), "wifi_bssid")?,
            ITEM_PROCESS_PATH_REGEX => unsupported(reader.read_strings(), "process_path_regex")?,
            ITEM_PACKAGE_NAME_REGEX => unsupported(reader.read_strings(), "package_name_regex")?,
            ITEM_ADGUARD_DOMAIN => {
                anyhow::bail!("binary rule item adguard_domain is not supported")
            }
            ITEM_NETWORK_TYPE => unsupported(reader.read_u8s(), "network_type")?,
            ITEM_NETWORK_IS_EXPENSIVE => {
                anyhow::bail!("binary rule item network_is_expensive is not supported")
            }
            ITEM_NETWORK_IS_CONSTRAINED => {
                anyhow::bail!("binary rule item network_is_constrained is not supported")
            }
            ITEM_NETWORK_INTERFACE_ADDRESS => {
                anyhow::bail!("binary rule item network_interface_address is not supported")
            }
            ITEM_DEFAULT_INTERFACE_ADDRESS => {
                anyhow::bail!("binary rule item default_interface_address is not supported")
            }
            item => anyhow::bail!("unknown binary rule item: {item}"),
        }
    }
}

fn unsupported<T>(decoded: Result<T>, name: &str) -> Result<()> {
    decoded?;
    anyhow::bail!("binary rule item {name} is not supported")
}

fn read_logical_rule(reader: &mut BinaryReader<'_>, depth: usize) -> Result<HeadlessRuleConfig> {
    let mode = match reader.read_u8()? {
        0 => "and",
        1 => "or",
        mode => anyhow::bail!("unknown logical rule mode: {mode}"),
    };
    let count = reader.read_count("logical rule count")?;
    let mut rules = Vec::with_capacity(count);
    for _ in 0..count {
        rules.push(read_rule(reader, depth)?);
    }
    Ok(HeadlessRuleConfig {
        kind: "logical".to_owned(),
        mode: mode.to_owned(),
        rules,
        invert: reader.read_bool()?,
        ..HeadlessRuleConfig::default()
    })
}

fn read_domain_matcher(reader: &mut BinaryReader<'_>) -> Result<(Vec<String>, Vec<String>)> {
    let set_version = reader.read_u8()?;
    anyhow::ensure!(
        set_version == 0,
        "unsupported domain matcher version: {set_version}"
    );
    let leaves = reader.read_u64s()?;
    let label_bitmap = reader.read_u64s()?;
    let labels = reader.read_bytes()?;
    let node_count = labels
        .len()
        .checked_add(1)
        .context("domain matcher is too large")?;
    anyhow::ensure!(
        leaves.len().saturating_mul(64) >= node_count,
        "invalid domain matcher leaves"
    );

    let mut children = vec![Vec::<(u8, usize)>::new(); node_count];
    let mut bit_index = 0usize;
    let mut label_index = 0usize;
    for node in &mut children {
        loop {
            let bit = get_bit(&label_bitmap, bit_index).context("invalid domain matcher bitmap")?;
            bit_index += 1;
            if bit {
                break;
            }
            let label = *labels
                .get(label_index)
                .context("invalid domain matcher labels")?;
            label_index += 1;
            node.push((label, label_index));
        }
    }
    anyhow::ensure!(label_index == labels.len(), "invalid domain matcher tree");

    let mut keys = Vec::new();
    collect_domain_keys(0, &children, &leaves, &mut Vec::new(), &mut keys)?;
    dump_domain_keys(keys)
}

fn collect_domain_keys(
    node: usize,
    children: &[Vec<(u8, usize)>],
    leaves: &[u64],
    current: &mut Vec<u8>,
    keys: &mut Vec<Vec<u8>>,
) -> Result<()> {
    anyhow::ensure!(current.len() <= 4096, "domain matcher key is too long");
    if get_bit(leaves, node).unwrap_or(false) {
        keys.push(current.clone());
    }
    for &(label, child) in &children[node] {
        anyhow::ensure!(child < children.len(), "invalid domain matcher child");
        current.push(label);
        collect_domain_keys(child, children, leaves, current, keys)?;
        current.pop();
    }
    Ok(())
}

fn dump_domain_keys(keys: Vec<Vec<u8>>) -> Result<(Vec<String>, Vec<String>)> {
    let mut exact = HashSet::new();
    let mut prefix = HashSet::new();
    let mut suffix = HashSet::new();
    for key in keys {
        let reversed = std::str::from_utf8(&key)
            .context("domain matcher contains invalid UTF-8")?
            .chars()
            .rev()
            .collect::<String>();
        if let Some(value) = reversed.strip_prefix('\r') {
            prefix.insert(value.to_owned());
        } else if let Some(value) = reversed.strip_prefix('\n') {
            suffix.insert(value.to_owned());
        } else {
            exact.insert(reversed);
        }
    }
    for value in prefix {
        if let Some(root) = value.strip_prefix('.')
            && exact.remove(root)
        {
            suffix.insert(root.to_owned());
            continue;
        }
        suffix.insert(value);
    }
    let mut exact = exact.into_iter().collect::<Vec<_>>();
    let mut suffix = suffix.into_iter().collect::<Vec<_>>();
    exact.sort_unstable();
    suffix.sort_unstable();
    Ok((exact, suffix))
}

fn read_ip_set(reader: &mut BinaryReader<'_>) -> Result<Vec<String>> {
    let version = reader.read_u8()?;
    anyhow::ensure!(version == 1, "unsupported IP set version: {version}");
    let count = reader.read_be_u64()?;
    anyhow::ensure!(count <= MAX_COLLECTION_SIZE, "IP set is too large");
    let mut cidrs = Vec::new();
    for _ in 0..count {
        let from = reader.read_bytes()?;
        let to = reader.read_bytes()?;
        match (from.as_slice(), to.as_slice()) {
            ([a, b, c, d], [e, f, g, h]) => {
                let from = u32::from_be_bytes([*a, *b, *c, *d]);
                let to = u32::from_be_bytes([*e, *f, *g, *h]);
                anyhow::ensure!(from <= to, "invalid IPv4 range in IP set");
                append_ipv4_range(&mut cidrs, from, to);
            }
            (from, to) if from.len() == 16 && to.len() == 16 => {
                let from = u128::from_be_bytes(from.try_into().expect("checked IPv6 length"));
                let to = u128::from_be_bytes(to.try_into().expect("checked IPv6 length"));
                anyhow::ensure!(from <= to, "invalid IPv6 range in IP set");
                append_ipv6_range(&mut cidrs, from, to);
            }
            _ => anyhow::bail!("invalid address length in IP set"),
        }
    }
    Ok(cidrs)
}

fn append_ipv4_range(output: &mut Vec<String>, mut start: u32, end: u32) {
    loop {
        let mut host_bits = start.trailing_zeros();
        while block_end_u32(start, host_bits) > end {
            host_bits -= 1;
        }
        output.push(format!("{}/{}", Ipv4Addr::from(start), 32 - host_bits));
        let block_end = block_end_u32(start, host_bits);
        if block_end == u32::MAX || block_end == end {
            break;
        }
        start = block_end + 1;
    }
}

fn block_end_u32(start: u32, host_bits: u32) -> u32 {
    if host_bits == 32 {
        u32::MAX
    } else {
        start | ((1u32 << host_bits) - 1)
    }
}

fn append_ipv6_range(output: &mut Vec<String>, mut start: u128, end: u128) {
    loop {
        let mut host_bits = start.trailing_zeros();
        while block_end_u128(start, host_bits) > end {
            host_bits -= 1;
        }
        output.push(format!("{}/{}", Ipv6Addr::from(start), 128 - host_bits));
        let block_end = block_end_u128(start, host_bits);
        if block_end == u128::MAX || block_end == end {
            break;
        }
        start = block_end + 1;
    }
}

fn block_end_u128(start: u128, host_bits: u32) -> u128 {
    if host_bits == 128 {
        u128::MAX
    } else {
        start | ((1u128 << host_bits) - 1)
    }
}

fn get_bit(words: &[u64], index: usize) -> Option<bool> {
    words
        .get(index >> 6)
        .map(|word| word & (1 << (index & 63)) != 0)
}

struct BinaryReader<'a> {
    cursor: Cursor<&'a [u8]>,
}

impl<'a> BinaryReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(input),
        }
    }

    fn is_empty(&self) -> bool {
        self.cursor.position() == self.cursor.get_ref().len() as u64
    }

    fn read_u8(&mut self) -> Result<u8> {
        let mut byte = [0];
        self.cursor
            .read_exact(&mut byte)
            .context("unexpected end of binary rule-set")?;
        Ok(byte[0])
    }

    fn read_bool(&mut self) -> Result<bool> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => anyhow::bail!("invalid boolean value: {value}"),
        }
    }

    fn read_be_u16(&mut self) -> Result<u16> {
        let mut bytes = [0; 2];
        self.cursor
            .read_exact(&mut bytes)
            .context("unexpected end of binary rule-set")?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_be_u64(&mut self) -> Result<u64> {
        let mut bytes = [0; 8];
        self.cursor
            .read_exact(&mut bytes)
            .context("unexpected end of binary rule-set")?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_uvarint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = self.read_u8()?;
            if shift == 63 && byte > 1 {
                anyhow::bail!("binary rule-set varint overflow");
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte < 0x80 {
                return Ok(value);
            }
        }
        anyhow::bail!("binary rule-set varint overflow")
    }

    fn read_count(&mut self, name: &str) -> Result<usize> {
        let count = self.read_uvarint()?;
        anyhow::ensure!(count <= MAX_COLLECTION_SIZE, "{name} is too large");
        usize::try_from(count).context("collection size exceeds platform limit")
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>> {
        let length = self.read_count("byte string")?;
        let mut bytes = vec![0; length];
        self.cursor
            .read_exact(&mut bytes)
            .context("unexpected end of binary rule-set")?;
        Ok(bytes)
    }

    fn read_strings(&mut self) -> Result<Vec<String>> {
        let count = self.read_count("string list")?;
        (0..count)
            .map(|_| {
                String::from_utf8(self.read_bytes()?).context("invalid UTF-8 in binary rule-set")
            })
            .collect()
    }

    fn read_u8s(&mut self) -> Result<Vec<u8>> {
        let count = self.read_count("byte list")?;
        let mut values = vec![0; count];
        self.cursor
            .read_exact(&mut values)
            .context("unexpected end of binary rule-set")?;
        Ok(values)
    }

    fn read_u16s(&mut self) -> Result<Vec<u16>> {
        let count = self.read_count("uint16 list")?;
        (0..count).map(|_| self.read_be_u16()).collect()
    }

    fn read_u64s(&mut self) -> Result<Vec<u64>> {
        let count = self.read_count("uint64 list")?;
        (0..count).map(|_| self.read_be_u64()).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{Compression, write::ZlibEncoder};

    use super::*;

    fn push_uvarint(output: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            output.push(value as u8 | 0x80);
            value >>= 7;
        }
        output.push(value as u8);
    }

    #[test]
    fn decodes_supported_official_binary_layout() {
        let mut payload = Vec::new();
        push_uvarint(&mut payload, 1);
        payload.extend([0, ITEM_NETWORK]);
        push_uvarint(&mut payload, 1);
        push_uvarint(&mut payload, 3);
        payload.extend(b"tcp");
        payload.push(ITEM_SOURCE_IP_CIDR);
        payload.push(1);
        payload.extend(1u64.to_be_bytes());
        push_uvarint(&mut payload, 4);
        payload.extend([192, 0, 2, 0]);
        push_uvarint(&mut payload, 4);
        payload.extend([192, 0, 2, 255]);
        payload.push(ITEM_PORT);
        push_uvarint(&mut payload, 1);
        payload.extend(443u16.to_be_bytes());
        payload.extend([ITEM_FINAL, 0]);

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&payload).unwrap();
        let mut encoded = b"SRS\x05".to_vec();
        encoded.extend(encoder.finish().unwrap());

        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.version, 5);
        assert_eq!(decoded.rules[0].network.as_slice(), &["tcp"]);
        assert_eq!(
            decoded.rules[0].source_ip_cidr.as_slice(),
            &["192.0.2.0/24"]
        );
        assert_eq!(decoded.rules[0].port.as_slice(), &[443]);
    }

    #[test]
    fn splits_ip_ranges_into_minimal_prefixes() {
        let mut output = Vec::new();
        append_ipv4_range(
            &mut output,
            u32::from(Ipv4Addr::new(192, 0, 2, 1)),
            u32::from(Ipv4Addr::new(192, 0, 2, 6)),
        );
        assert_eq!(
            output,
            [
                "192.0.2.1/32",
                "192.0.2.2/31",
                "192.0.2.4/31",
                "192.0.2.6/32"
            ]
        );
    }

    #[test]
    fn decodes_fixture_compiled_by_official_sing_box() {
        let encoded = include_bytes!("../../../examples/rule-set/compat.srs");
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.rules.len(), 2);
        assert_eq!(
            decoded.rules[0].domain.as_slice(),
            &["example.com", "rust-lang.org"]
        );
        assert_eq!(
            decoded.rules[0].domain_suffix.as_slice(),
            &[".internal.example", "example.net"]
        );
        assert_eq!(
            decoded.rules[0].source_ip_cidr.as_slice(),
            &["192.0.2.0/24", "2001:db8::/32"]
        );
        assert_eq!(decoded.rules[1].kind, "logical");
        assert_eq!(decoded.rules[1].mode, "or");
        assert_eq!(decoded.rules[1].rules.len(), 2);
    }
}
