//! Comprehensive integration & conformance tests for WP-55 Tranche 2
//! (`fg-waf-engine` SecLang parser, transforms, operators, 5-phase transaction
//! evaluator, anomaly scoring, body parsers, SQLi/XSS detection, persistent
//! collections, and regex prefilter).

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use fg_waf_engine::{
    BodyLimitAction, BodyProcessor, InterventionAction, Phase, Prefilter, RequestHead,
    ResponseHead, RuleEngineMode, Transform, Waf, WafConfig, apply_transform, apply_transforms,
    body::{parse_json, parse_multipart, parse_urlencoded, parse_xml},
    detect_sqli, detect_xss,
    seclang::parse,
};

#[test]
fn parser_crs_style_directives_and_includes_zero_failures() {
    let mut includes = HashMap::new();
    includes.insert(
        "rules/01-setup.conf".to_owned(),
        r#"
# CRS-style setup file
SecComponentSignature "OWASP_CRS/4.25.0"
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyLimitAction Reject
SecResponseBodyAccess On
SecResponseBodyLimit 524288
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
SecCollectionTimeout 600
SecArgumentSeparator &
SecAuditEngine RelevantOnly
SecAuditLogParts ABIJDEFHZ
"#
        .to_owned(),
    );
    includes.insert(
        "rules/02-rules.conf".to_owned(),
        r#"
SecRule REQUEST_METHOD "!@within %{tx.allowed_methods}" \
    "id:911100,\
    phase:1,\
    block,\
    t:none,\
    msg:'Method is not allowed by policy',\
    logdata:'%{MATCHED_VAR}',\
    severity:'CRITICAL',\
    tag:'application-multi',\
    tag:'attack-generic',\
    ver:'OWASP_CRS/4.25.0',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

SecAction \
    "id:900990,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    setvar:'tx.crs_setup_version=4250'"

SecMarker END-CRS
"#
        .to_owned(),
    );

    let root = r#"
Include rules/*.conf
SecRuleRemoveById 999999
"#;

    let waf = Waf::from_seclang_with_includes(WafConfig::default(), root, &includes)
        .expect("CRS-style config compiles with zero errors");
    assert_eq!(waf.rule_count(), 2);
    assert!(waf.warnings().is_empty());

    let mut tx = waf.new_transaction();
    tx.process_request_headers(&RequestHead::new("TRACE", "/"));
    tx.process_request_body(b"");
    assert_eq!(tx.tx_var("crs_setup_version"), Some("4250"));
    assert_eq!(tx.inbound_score(), 5);
    assert!(tx.intervention().is_some());
}

#[test]
fn parser_reports_unsupported_operators_and_skips_rules_cleanly() {
    let rules = r#"
SecRule REQUEST_BODY "@validateSchema openapi.json" "id:1001,phase:2,deny"
SecRule REMOTE_ADDR "@rbl sbl.spamhaus.org" "id:1002,phase:1,deny"
SecRule REMOTE_ADDR "@geoLookup" "id:1003,phase:1,pass"
SecRule REQUEST_BODY "@fuzzyHash ssdeep.txt" "id:1004,phase:2,deny"
SecRule ARGS "@gsbLookup" "id:1005,phase:2,deny"
SecRule ARGS "@verifyCC \d{13,16}" "id:1006,phase:2,deny"
# Unsupported regex backreference should also warn & skip cleanly rather than fail compilation
SecRule ARGS "@rx (\w+)\s+\1" "id:1007,phase:2,deny"
# Valid rule must still compile and run
SecRule ARGS "@contains evil" "id:1008,phase:2,deny,status:403,msg:'Blocked evil'"
"#;

    let waf = Waf::from_seclang(WafConfig::default(), rules).expect("compiles with warnings");
    assert_eq!(waf.rule_count(), 1, "only valid rule compiles");
    assert_eq!(waf.warnings().len(), 7, "all 7 unsupported rules recorded");
    assert!(
        waf.warnings()
            .iter()
            .any(|w| w.rule_id == Some(1001) && w.message.contains("validateschema"))
    );
    assert!(
        waf.warnings()
            .iter()
            .any(|w| w.rule_id == Some(1007) && w.message.contains("@rx"))
    );

    let mut tx = waf.new_transaction();
    tx.process_request_headers(&RequestHead::new("GET", "/?q=evil"));
    tx.process_request_body(b"");
    assert_eq!(tx.intervention().map(|i| i.rule_id), Some(1008));
}

#[test]
fn parser_linear_on_adversarial_input() {
    // Construct a large adversarial input with thousands of lines, continuations,
    // escaped quotes, pipes, and comments.
    let mut big = String::with_capacity(250_000);
    for i in 0..2_000 {
        big.push_str(&format!(
            "# comment {i}\nSecRule ARGS|ARGS_NAMES|!ARGS:ok_{i} \"@contains tok_{i}\" \\\n  \"id:{},phase:2,pass,msg:'a, b, \\'c\\''\"\n",
            10_000 + i
        ));
    }
    let start = Instant::now();
    let dirs = parse("adversarial.conf", &big).expect("parses cleanly");
    let elapsed = start.elapsed();
    assert_eq!(dirs.len(), 2_000);
    assert!(
        elapsed < Duration::from_secs(2),
        "parser must stay linear time, took {elapsed:?}"
    );
}

#[test]
fn transforms_match_modsecurity_semantics() {
    assert_eq!(apply_transform(Transform::None, "MiXeD"), "MiXeD");
    assert_eq!(apply_transform(Transform::Lowercase, "MiXeD"), "mixed");
    assert_eq!(
        apply_transform(Transform::UrlDecode, "a+b%20%3C%3E%2f"),
        "a b <>/"
    );
    assert_eq!(
        apply_transform(Transform::UrlDecodeUni, "%u0027%uff0f%20x"),
        "'/ x"
    );
    assert_eq!(
        apply_transform(
            Transform::HtmlEntityDecode,
            "&amp;&lt;&gt;&quot;&apos;&#65;&#x42;"
        ),
        "&<>\"'AB"
    );
    assert_eq!(
        apply_transform(Transform::JsDecode, r"\u0041\x42\103\n\t\'"),
        "ABC\n\t'"
    );
    assert_eq!(
        apply_transform(Transform::CssDecode, r"\41 \000042\43"),
        "ABC"
    );
    assert_eq!(apply_transform(Transform::RemoveNulls, "a\0b\0"), "ab");
    assert_eq!(
        apply_transform(Transform::RemoveWhitespace, " \ta\r\nb\x0bc "),
        "abc"
    );
    assert_eq!(
        apply_transform(Transform::ReplaceComments, "SELECT/*x*/1/*y*/FROM/*z"),
        "SELECT 1 FROM "
    );
    assert_eq!(
        apply_transform(Transform::CompressWhitespace, "a   \t\r\n  b"),
        "a b"
    );
    assert_eq!(
        apply_transform(Transform::NormalizePath, "/var/www/../etc/./passwd"),
        "/var/etc/passwd"
    );
    assert_eq!(
        apply_transform(
            Transform::NormalizePathWin,
            r"C:\Windows\..\System32\cmd.exe"
        ),
        "C:/System32/cmd.exe"
    );
    assert_eq!(
        apply_transform(Transform::CmdLine, r#"w^h"o"a'm'i; /bin/sh  (id)"#),
        "whoami/bin/sh(id)"
    );
    assert_eq!(
        apply_transform(Transform::HexDecode, "73656c656374"),
        "select"
    );
    assert_eq!(
        apply_transform(Transform::HexEncode, "select"),
        "73656c656374"
    );
    assert_eq!(
        apply_transform(Transform::EscapeSeqDecode, r"\x73\x71\x6c\n\t"),
        "sql\n\t"
    );

    // Chained transforms in order.
    let chain = [
        Transform::UrlDecodeUni,
        Transform::HtmlEntityDecode,
        Transform::RemoveNulls,
        Transform::ReplaceComments,
        Transform::CompressWhitespace,
        Transform::Lowercase,
    ];
    assert_eq!(
        apply_transforms(&chain, "UN%00ION/*bypass*/%20&#83;ELECT"),
        "union select"
    );

    // Verify `t:none` resets default action transforms in SecLang.
    let rules = r#"
SecDefaultAction "phase:2,pass,t:lowercase"
SecRule ARGS:a "@streq HELLO" "id:1,phase:2,t:none,deny,msg:'exact uppercase'"
SecRule ARGS:b "@streq hello" "id:2,phase:2,deny,msg:'inherited lowercase'"
"#;
    let waf = Waf::from_seclang(WafConfig::default(), rules).expect("compiles");
    let mut tx1 = waf.new_transaction();
    tx1.process_request_headers(&RequestHead::new("GET", "/?a=HELLO"));
    tx1.process_request_body(b"");
    assert_eq!(tx1.intervention().map(|i| i.rule_id), Some(1));

    let mut tx2 = waf.new_transaction();
    tx2.process_request_headers(&RequestHead::new("GET", "/?b=HELLO"));
    tx2.process_request_body(b"");
    assert_eq!(tx2.intervention().map(|i| i.rule_id), Some(2));
}

#[test]
fn operators_unit_every_supported_operator() {
    let mut data_files = HashMap::new();
    data_files.insert(
        "bad-bots.data".to_owned(),
        "# comment\nsqlmap\nnikto\n".to_owned(),
    );
    data_files.insert("banned-ips.data".to_owned(), "203.0.113.0/24\n".to_owned());

    let rules = r#"
SecRule ARGS:rx "@rx ^foo[0-9]+$" "id:1,phase:2,pass,capture,setvar:'tx.hit_rx=%{tx.0}'"
SecRule ARGS:pm "@pm alpha beta gamma" "id:2,phase:2,pass,setvar:'tx.hit_pm=1'"
SecRule ARGS:pmf "@pmFromFile bad-bots.data" "id:3,phase:2,pass,setvar:'tx.hit_pmf=1'"
SecRule ARGS:cnt "@contains needle" "id:4,phase:2,pass,setvar:'tx.hit_cnt=1'"
SecRule ARGS:eqs "@streq exact" "id:5,phase:2,pass,setvar:'tx.hit_streq=1'"
SecRule ARGS:sw "@startsWith pre_" "id:6,phase:2,pass,setvar:'tx.hit_sw=1'"
SecRule ARGS:ew "@endsWith _suf" "id:7,phase:2,pass,setvar:'tx.hit_ew=1'"
SecRule REQUEST_METHOD "@within GET POST PUT" "id:8,phase:2,pass,setvar:'tx.hit_within=1'"
SecRule ARGS:num "@eq 42" "id:9,phase:2,pass,setvar:'tx.hit_eq=1'"
SecRule ARGS:num "@gt 40" "id:10,phase:2,pass,setvar:'tx.hit_gt=1'"
SecRule ARGS:num "@lt 50" "id:11,phase:2,pass,setvar:'tx.hit_lt=1'"
SecRule ARGS:num "@ge 42" "id:12,phase:2,pass,setvar:'tx.hit_ge=1'"
SecRule ARGS:num "@le 42" "id:13,phase:2,pass,setvar:'tx.hit_le=1'"
SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8,192.168.1.1" "id:14,phase:2,pass,setvar:'tx.hit_ip=1'"
SecRule REMOTE_ADDR "@ipMatchFromFile banned-ips.data" "id:15,phase:2,pass,setvar:'tx.hit_ipf=1'"
SecRule REQUEST_BODY "@validateByteRange 32-126" "id:16,phase:2,pass,setvar:'tx.hit_br=1'"
SecRule REQUEST_BODY "@validateUTF8" "id:17,phase:2,pass,setvar:'tx.hit_utf8=1'"
SecRule ARGS:any "@unconditionalMatch" "id:18,phase:2,pass,setvar:'tx.hit_uncond=1'"
SecRule ARGS:any "@noMatch" "id:19,phase:2,pass,setvar:'tx.hit_nomatch=1'"
SecRule ARGS:sqli "@detectSQLi" "id:20,phase:2,pass,setvar:'tx.hit_sqli=1'"
SecRule ARGS:xss "@detectXSS" "id:21,phase:2,pass,setvar:'tx.hit_xss=1'"
SecRule REQUEST_METHOD "!@streq DELETE" "id:22,phase:2,pass,setvar:'tx.hit_neg=1'"
"#;

    let waf = Waf::from_seclang_with_data(
        WafConfig {
            inbound_threshold: 0,
            ..Default::default()
        },
        rules,
        &HashMap::new(),
        &data_files,
    )
    .expect("all operators compile");

    let uri = "/?rx=foo99&pm=Hello+BETA&pmf=SQLMap/1.7&cnt=hayneedle&eqs=exact&sw=pre_1&ew=1_suf&num=42&any=x&sqli=1+OR+1%3D1&xss=%3Cscript%3Ealert(1)%3C%2Fscript%3E";
    let mut tx = waf.new_transaction();
    tx.process_request_headers(
        &RequestHead::new("POST", uri).with_remote_addr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
    );
    // Body has invalid UTF-8 and out-of-range byte 0x01 and 0xff
    tx.process_request_body(&[0x41, 0x01, 0xff]);

    assert_eq!(tx.tx_var("hit_rx"), Some("foo99"));
    assert_eq!(tx.tx_var("hit_pm"), Some("1"));
    assert_eq!(tx.tx_var("hit_pmf"), Some("1"));
    assert_eq!(tx.tx_var("hit_cnt"), Some("1"));
    assert_eq!(tx.tx_var("hit_streq"), Some("1"));
    assert_eq!(tx.tx_var("hit_sw"), Some("1"));
    assert_eq!(tx.tx_var("hit_ew"), Some("1"));
    assert_eq!(tx.tx_var("hit_within"), Some("1"));
    assert_eq!(tx.tx_var("hit_eq"), Some("1"));
    assert_eq!(tx.tx_var("hit_gt"), Some("1"));
    assert_eq!(tx.tx_var("hit_lt"), Some("1"));
    assert_eq!(tx.tx_var("hit_ge"), Some("1"));
    assert_eq!(tx.tx_var("hit_le"), Some("1"));
    assert_eq!(tx.tx_var("hit_ip"), Some("1"));
    assert_eq!(tx.tx_var("hit_ipf"), None);
    assert_eq!(tx.tx_var("hit_br"), Some("1"));
    assert_eq!(tx.tx_var("hit_utf8"), Some("1"));
    assert_eq!(tx.tx_var("hit_uncond"), Some("1"));
    assert_eq!(tx.tx_var("hit_nomatch"), None);
    assert_eq!(tx.tx_var("hit_sqli"), Some("1"));
    assert_eq!(tx.tx_var("hit_xss"), Some("1"));
    assert_eq!(tx.tx_var("hit_neg"), Some("1"));

    // Verify @ipMatchFromFile hits for 203.0.113.55
    let mut tx2 = waf.new_transaction();
    tx2.process_request_headers(
        &RequestHead::new("GET", "/").with_remote_addr(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55))),
    );
    tx2.process_request_body(b"clean ascii");
    assert_eq!(tx2.tx_var("hit_ipf"), Some("1"));
    assert_eq!(tx2.tx_var("hit_br"), None);
    assert_eq!(tx2.tx_var("hit_utf8"), None);
}

#[test]
fn transaction_phase_order() {
    let rules = r#"
SecRule REQUEST_METHOD "@streq POST" "id:101,phase:1,pass,setvar:'tx.p1=1'"
SecRule REQUEST_BODY "@contains secret" "id:102,phase:2,pass,setvar:'tx.p2=1'"
SecRule RESPONSE_STATUS "@eq 200" "id:103,phase:3,pass,setvar:'tx.p3=1'"
SecRule RESPONSE_BODY "@contains leak" "id:104,phase:4,pass,setvar:'tx.p4=1'"
SecAction "id:105,phase:5,pass,setvar:'tx.p5=1'"
"#;
    let waf = Waf::from_seclang(WafConfig::default(), rules).expect("compiles");
    let mut tx = waf.new_transaction();
    tx.process_request_headers(&RequestHead::new("POST", "/submit"));
    tx.process_request_body(b"payload=secret");
    tx.process_response_headers(&ResponseHead::new(200).with_header("Content-Type", "text/plain"));
    tx.process_response_body(b"data leak");
    tx.process_logging();

    assert_eq!(
        tx.phases_executed(),
        &[
            Phase::RequestHeaders,
            Phase::RequestBody,
            Phase::ResponseHeaders,
            Phase::ResponseBody,
            Phase::Logging,
        ]
    );
    let ids: Vec<u64> = tx.matched_rules().iter().map(|m| m.id).collect();
    assert_eq!(ids, vec![101, 102, 103, 104, 105]);
    assert_eq!(tx.tx_var("p5"), Some("1"));
}

#[test]
fn chain_rule_stops_on_first_nonmatch() {
    let rules = r#"
SecRule REQUEST_METHOD "@streq POST" \
    "id:2001,phase:2,deny,status:403,chain,msg:'Chained admin block',setvar:'tx.chain_fired=1'"
    SecRule REQUEST_URI "@rx ^/admin/([a-z]+)$" "capture,chain"
        SecRule TX:1 "@streq delete" "setvar:'tx.child_ran=1'"
"#;
    let waf = Waf::from_seclang(WafConfig::default(), rules).expect("compiles");

    // Link 1 fails (GET != POST): link 2 and 3 must not run, no setvar, no match.
    let mut tx1 = waf.new_transaction();
    tx1.process_request_headers(&RequestHead::new("GET", "/admin/delete"));
    tx1.process_request_body(b"");
    assert!(tx1.intervention().is_none());
    assert!(tx1.matched_rules().is_empty());
    assert_eq!(tx1.tx_var("chain_fired"), None);
    assert_eq!(tx1.tx_var("child_ran"), None);

    // Link 1 matches, link 2 matches (TX:1 = "view"), link 3 fails -> must NOT fire starter actions!
    let mut tx2 = waf.new_transaction();
    tx2.process_request_headers(&RequestHead::new("POST", "/admin/view"));
    tx2.process_request_body(b"");
    assert!(tx2.intervention().is_none());
    assert!(tx2.matched_rules().is_empty());
    assert_eq!(tx2.tx_var("chain_fired"), None);
    assert_eq!(tx2.tx_var("child_ran"), None);

    // All 3 links match -> fires starter + child actions and denies.
    let mut tx3 = waf.new_transaction();
    tx3.process_request_headers(&RequestHead::new("POST", "/admin/delete"));
    tx3.process_request_body(b"");
    assert_eq!(tx3.intervention().map(|i| i.rule_id), Some(2001));
    assert_eq!(tx3.tx_var("chain_fired"), Some("1"));
    assert_eq!(tx3.tx_var("child_ran"), Some("1"));
    assert_eq!(tx3.matched_rules().len(), 1);
}

#[test]
fn skip_skipafter_secmarker_and_ctl_runtime_overrides() {
    let rules = r#"
SecRule REQUEST_URI "@beginsWith /health" "id:1,phase:1,allow"
SecRule REQUEST_URI "@startsWith /skip-two" "id:2,phase:1,pass,skip:2"
SecAction "id:3,phase:1,pass,setvar:'tx.r3=1'"
SecAction "id:4,phase:1,pass,setvar:'tx.r4=1'"
SecAction "id:5,phase:1,pass,setvar:'tx.r5=1'"

SecRule REQUEST_URI "@startsWith /jump" "id:6,phase:1,pass,skipAfter:END_BLOCK"
SecAction "id:7,phase:1,pass,setvar:'tx.r7=1'"
SecMarker END_BLOCK
SecAction "id:8,phase:1,pass,setvar:'tx.r8=1'"

SecRule REQUEST_HEADERS:X-Bypass-Id "@streq yes" "id:9,phase:1,pass,ctl:ruleRemoveById=10"
SecRule ARGS:q "@contains bad" "id:10,phase:2,deny"

SecRule REQUEST_HEADERS:X-Detect-Only "@streq yes" "id:11,phase:1,pass,ctl:ruleEngine=DetectionOnly"
"#;
    // Note: `@beginsWith` is an unsupported alias (SecLang uses `@startsWith`), so id:1 is skipped cleanly.
    let waf = Waf::from_seclang(WafConfig::default(), rules).expect("compiles");

    let mut tx = waf.new_transaction();
    tx.process_request_headers(&RequestHead::new("GET", "/skip-two"));
    assert_eq!(tx.tx_var("r3"), None);
    assert_eq!(tx.tx_var("r4"), None);
    assert_eq!(tx.tx_var("r5"), Some("1"));

    let mut tx2 = waf.new_transaction();
    tx2.process_request_headers(&RequestHead::new("GET", "/jump"));
    assert_eq!(tx2.tx_var("r7"), None);
    assert_eq!(tx2.tx_var("r8"), Some("1"));

    // ctl:ruleRemoveById=10 prevents rule 10 from blocking.
    let mut tx3 = waf.new_transaction();
    tx3.process_request_headers(
        &RequestHead::new("GET", "/?q=bad").with_header("X-Bypass-Id", "yes"),
    );
    tx3.process_request_body(b"");
    assert!(tx3.intervention().is_none());

    // ctl:ruleEngine=DetectionOnly records match without blocking.
    let mut tx4 = waf.new_transaction();
    tx4.process_request_headers(
        &RequestHead::new("GET", "/?q=bad").with_header("X-Detect-Only", "yes"),
    );
    tx4.process_request_body(b"");
    assert_eq!(tx4.rule_engine_mode(), RuleEngineMode::DetectionOnly);
    assert!(tx4.intervention().is_none());
    assert!(tx4.matched_rules().iter().any(|m| m.id == 10));
}

#[test]
fn anomaly_scores_accumulate_inbound_and_outbound() {
    let rules = r#"
SecRule ARGS "@contains union" \
    "id:942100,phase:2,pass,severity:'WARNING',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}'"
SecRule ARGS "@contains select" \
    "id:942110,phase:2,pass,severity:'WARNING',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}'"
SecRule RESPONSE_BODY "@contains SQL syntax error" \
    "id:951100,phase:4,pass,severity:'ERROR',setvar:'tx.outbound_anomaly_score_pl1=+%{tx.error_anomaly_score}'"
"#;
    let waf = Waf::from_seclang(
        WafConfig {
            inbound_threshold: 5,
            outbound_threshold: 4,
            ..Default::default()
        },
        rules,
    )
    .expect("compiles");

    // Single warning (score 3 < 5): passes inbound, then outbound error (4 >= 4) blocks!
    let mut tx1 = waf.new_transaction();
    tx1.process_request_headers(&RequestHead::new("GET", "/?q=union"));
    tx1.process_request_body(b"");
    assert_eq!(tx1.inbound_score(), 3);
    assert!(tx1.intervention().is_none());

    tx1.process_response_headers(&ResponseHead::new(500));
    tx1.process_response_body(b"MySQL: SQL syntax error near ''");
    assert_eq!(tx1.outbound_score(), 4);
    assert_eq!(tx1.intervention().map(|i| i.status), Some(403));

    // Two warnings (3 + 3 = 6 >= 5): blocks inbound.
    let mut tx2 = waf.new_transaction();
    tx2.process_request_headers(&RequestHead::new("GET", "/?q=union+select"));
    tx2.process_request_body(b"");
    assert_eq!(tx2.inbound_score(), 6);
    assert_eq!(tx2.intervention().map(|i| i.status), Some(403));
    assert_eq!(tx2.matched_rules().len(), 2);
}

#[test]
fn paranoia_level_filters_rules() {
    let rules = r#"
SecRule ARGS "@contains p1" "id:100,phase:2,pass,tag:'paranoia-level/1',setvar:'tx.inbound_anomaly_score_pl1=+5'"
SecRule ARGS "@contains p2" "id:200,phase:2,pass,tag:'paranoia-level/2',setvar:'tx.inbound_anomaly_score_pl2=+5'"
SecRule TX:PARANOIA_LEVEL "@lt 3" "id:299,phase:2,pass,nolog,skipAfter:END_PL3"
SecRule ARGS "@contains p3" "id:300,phase:2,pass,setvar:'tx.inbound_anomaly_score_pl3=+5'"
SecMarker END_PL3
"#;

    let waf_pl1 = Waf::from_seclang(
        WafConfig {
            paranoia_level: 1,
            ..Default::default()
        },
        rules,
    )
    .expect("compiles");
    let mut tx1 = waf_pl1.new_transaction();
    tx1.process_request_headers(&RequestHead::new("GET", "/?a=p2&b=p3"));
    tx1.process_request_body(b"");
    assert_eq!(tx1.inbound_score(), 0);
    assert!(tx1.intervention().is_none());

    let waf_pl3 = Waf::from_seclang(
        WafConfig {
            paranoia_level: 3,
            ..Default::default()
        },
        rules,
    )
    .expect("compiles");
    let mut tx3 = waf_pl3.new_transaction();
    tx3.process_request_headers(&RequestHead::new("GET", "/?a=p2&b=p3"));
    tx3.process_request_body(b"");
    assert_eq!(tx3.inbound_score(), 10);
    assert!(tx3.intervention().is_some());
}

#[test]
fn webdav_mode_and_body_limit_actions() {
    let rules = r#"
SecRule REQUEST_METHOD "!@within %{tx.allowed_methods}" "id:911100,phase:1,deny,status:405"
SecRule REQUEST_BODY "@contains tail_marker" "id:999001,phase:2,deny"
"#;

    // Default (webdav=false) blocks PROPFIND and rejects oversized body with 413.
    let waf_strict = Waf::from_seclang(
        WafConfig {
            webdav: false,
            request_body_limit: 16,
            request_body_limit_action: BodyLimitAction::Reject,
            ..Default::default()
        },
        rules,
    )
    .expect("compiles");

    let mut tx_dav = waf_strict.new_transaction();
    tx_dav.process_request_headers(&RequestHead::new("PROPFIND", "/dav/"));
    assert_eq!(tx_dav.intervention().map(|i| i.status), Some(405));

    let mut tx_big = waf_strict.new_transaction();
    tx_big.process_request_headers(&RequestHead::new("POST", "/upload"));
    tx_big.process_request_body(b"0123456789abcdef_tail_marker");
    assert_eq!(tx_big.intervention().map(|i| i.status), Some(413));

    // WebDAV + ProcessPartial allows PROPFIND and only inspects first 16 bytes.
    let waf_dav = Waf::from_seclang(
        WafConfig {
            webdav: true,
            request_body_limit: 16,
            request_body_limit_action: BodyLimitAction::ProcessPartial,
            ..Default::default()
        },
        rules,
    )
    .expect("compiles");

    let mut tx_ok = waf_dav.new_transaction();
    tx_ok.process_request_headers(&RequestHead::new("PROPFIND", "/dav/"));
    tx_ok.process_request_body(b"0123456789abcdef_tail_marker");
    assert!(tx_ok.intervention().is_none());
}

#[test]
fn body_parsers_urlencoded_multipart_xml_json_and_malformed() {
    // Urlencoded
    let u = parse_urlencoded(b"x=hello+world&y=%27%20OR%201%3D1--", b'&', 100);
    assert_eq!(u.processor, BodyProcessor::UrlEncoded);
    assert_eq!(u.args[1], ("y".into(), "' OR 1=1--".into()));

    // Multipart with field + file upload
    let mp = parse_multipart(
        b"--B\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\n<script>alert(1)</script>\r\n--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"evil.jsp\"\r\n\r\nPAYLOAD\r\n--B--\r\n",
        "multipart/form-data; boundary=\"B\"",
        32,
    );
    assert!(mp.parse_error.is_none());
    assert_eq!(mp.args[0].1, "<script>alert(1)</script>");
    assert_eq!(mp.files, vec!["evil.jsp".to_owned()]);
    assert_eq!(mp.files_names, vec!["file".to_owned()]);

    // JSON with deep nesting bound
    let mut deep_json = String::new();
    for _ in 0..80 {
        deep_json.push_str(r#"{"a":"#);
    }
    deep_json.push('1');
    for _ in 0..80 {
        deep_json.push('}');
    }
    let j = parse_json(deep_json.as_bytes(), 100, 16);
    assert!(j.truncated);

    // XML with DOCTYPE (XXE must not expand) + CDATA + attributes
    let xml = parse_xml(
        br#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><req role="admin"><q>&lt;script&gt;</q><raw><![CDATA[' OR 1=1--]]></raw></req>"#,
        100,
        16,
    );
    assert!(xml.parse_error.is_none());
    assert_eq!(xml.xml_attrs, vec![("role".into(), "admin".into())]);
    assert_eq!(
        xml.xml_texts,
        vec!["<script>".to_owned(), "' OR 1=1--".to_owned()]
    );

    // Malformed / adversarial inputs never panic
    for bad in [
        &b""[..],
        &b"\x00\xff\xfe\x80"[..],
        &b"<<<<<<<<<"[..],
        &b"<!-- unterminated"[..],
        &b"<![CDATA[unterminated"[..],
        &b"{\"broken\": [1, 2,"[..],
        &b"--bound\r\nnoheaders"[..],
    ] {
        let _ = parse_urlencoded(bad, b'&', 16);
        let _ = parse_multipart(bad, "multipart/form-data; boundary=bound", 16);
        let _ = parse_json(bad, 16, 8);
        let _ = parse_xml(bad, 16, 8);
    }

    // End-to-end JSON & XML inspection in Transaction
    let rules = r#"
SecRule ARGS_POST "@detectSQLi" "id:5001,phase:2,deny,msg:'SQLi in parsed body'"
SecRule FILES "@rx \.(php|jsp)$" "id:5002,phase:2,deny,msg:'Dangerous upload'"
SecRule XML "@detectXSS" "id:5003,phase:2,deny,msg:'XSS in XML'"
SecRule REQBODY_ERROR "@eq 1" "id:5004,phase:2,deny,status:400,msg:'Malformed body'"
"#;
    let waf = Waf::from_seclang(WafConfig::default(), rules).expect("compiles");

    // JSON SQLi
    let mut tx_json = waf.new_transaction();
    tx_json.process_request_headers(
        &RequestHead::new("POST", "/api/users").with_header("Content-Type", "application/json"),
    );
    tx_json.process_request_body(br#"{"filter":{"name":"admin' OR '1'='1"}}"#);
    assert_eq!(tx_json.intervention().map(|i| i.rule_id), Some(5001));

    // Malformed JSON triggers REQBODY_ERROR
    let mut tx_bad = waf.new_transaction();
    tx_bad.process_request_headers(
        &RequestHead::new("POST", "/api/users").with_header("Content-Type", "application/json"),
    );
    tx_bad.process_request_body(br#"{"unclosed":"#);
    assert_eq!(tx_bad.intervention().map(|i| i.rule_id), Some(5004));
    assert!(tx_bad.body_parse_error().is_some());

    // XML XSS
    let mut tx_xml = waf.new_transaction();
    tx_xml.process_request_headers(
        &RequestHead::new("POST", "/soap").with_header("Content-Type", "application/xml"),
    );
    tx_xml.process_request_body(b"<note><body>&lt;img src=x onerror=alert(1)&gt;</body></note>");
    assert_eq!(tx_xml.intervention().map(|i| i.rule_id), Some(5003));
}

#[test]
fn sqli_and_xss_payloads_blocked_and_low_false_positives_on_common_apps() {
    let rules = r#"
SecRule REQUEST_URI|ARGS|REQUEST_COOKIES|REQUEST_HEADERS:Cookie "@detectSQLi" \
    "id:942100,phase:2,block,t:none,t:urlDecodeUni,msg:'SQL Injection Attack Detected via libinjection',severity:'CRITICAL',setvar:'tx.inbound_anomaly_score_pl1=+5'"
SecRule REQUEST_URI|ARGS|REQUEST_COOKIES "@detectXSS" \
    "id:941100,phase:2,block,t:none,t:urlDecodeUni,t:htmlEntityDecode,msg:'XSS Attack Detected via libinjection',severity:'CRITICAL',setvar:'tx.inbound_anomaly_score_pl1=+5'"
SecRule REQUEST_URI|ARGS "@rx (?i)(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow)" \
    "id:930100,phase:2,block,t:none,t:urlDecodeUni,t:normalizePathWin,msg:'Path Traversal Attack',severity:'CRITICAL',setvar:'tx.inbound_anomaly_score_pl1=+5'"
SecRule ARGS "@rx (?i)(?:;|\|\||&&|\|)\s*(?:cat|id|whoami|uname|wget|curl|/bin/sh)\b" \
    "id:932100,phase:2,block,t:none,t:urlDecodeUni,msg:'Remote Command Execution',severity:'CRITICAL',setvar:'tx.inbound_anomaly_score_pl1=+5'"
"#;
    let waf = Waf::from_seclang(WafConfig::default(), rules).expect("compiles");

    let attack_requests = [
        RequestHead::new("GET", "/login?user=admin%27%20OR%20%271%27%3D%271"),
        RequestHead::new("GET", "/items?id=1+UNION+SELECT+1,password+FROM+users"),
        RequestHead::new("GET", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
        RequestHead::new("GET", "/profile?bio=%3Csvg%20onload%3Dalert(1)%3E"),
        RequestHead::new("GET", "/files?path=../../../../etc/passwd"),
        RequestHead::new("GET", "/ping?host=127.0.0.1;cat+/etc/passwd"),
        RequestHead::new("GET", "/").with_header("Cookie", "session=abc' OR '1'='1"),
        RequestHead::new("GET", "/").with_header("Cookie", "session='; DROP TABLE sessions--"),
    ];
    for req in &attack_requests {
        let mut tx = waf.new_transaction();
        tx.process_request_headers(req);
        tx.process_request_body(b"");
        assert_eq!(
            tx.intervention().map(|i| &i.action),
            Some(&InterventionAction::Deny),
            "expected attack to be blocked: {} {}",
            req.method,
            req.uri
        );
    }

    // Normal web application requests must pass cleanly with zero false positives.
    let benign_requests: Vec<(RequestHead, &[u8])> = vec![
        (
            RequestHead::new("GET", "/api/v1/articles?q=how+to+select+a+database&page=2")
                .with_header("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)")
                .with_header("Cookie", "theme=dark; locale=en-US"),
            b"",
        ),
        (
            RequestHead::new("POST", "/api/v1/users")
                .with_header("Content-Type", "application/json")
                .with_header("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"),
            br#"{"name":"Patrick O'Brien","email":"Alice <alice@example.com>","bio":"I love union stations and reading JavaScript: The Good Parts."}"#,
        ),
        (
            RequestHead::new("POST", "/contact")
                .with_header("Content-Type", "application/x-www-form-urlencoded"),
            b"subject=Order+status&message=Please+update+my+shipping+address+or+drop+by+on+Monday",
        ),
    ];
    for (req, body) in &benign_requests {
        let mut tx = waf.new_transaction();
        tx.process_request_headers(req);
        tx.process_request_body(body);
        assert!(
            tx.intervention().is_none(),
            "false positive on benign request {} {}: {:?}",
            req.method,
            req.uri,
            tx.matched_rules()
        );
        assert_eq!(tx.inbound_score(), 0);
    }

    // Direct detector sanity checks
    assert!(detect_sqli("1' AND SLEEP(5)--").is_some());
    assert!(detect_xss("javascript:alert(1)").is_some());
}

#[test]
fn persistent_collections_expire() {
    let rules = r#"
SecAction "id:1,phase:1,pass,nolog,initcol:ip=%{REMOTE_ADDR}"
SecRule REQUEST_URI "@streq /login" "id:2,phase:1,pass,setvar:'ip.login_tries=+1',expirevar:'ip.login_tries=10'"
SecRule IP:login_tries "@ge 3" "id:3,phase:1,deny,status:429,msg:'Rate limit exceeded'"
"#;
    let waf = Waf::from_seclang(WafConfig::default(), rules).expect("compiles");
    let client = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    let t0 = Instant::now();

    // T+0s: try 1 -> pass
    let mut tx1 = waf.new_transaction_at(t0);
    tx1.process_request_headers(&RequestHead::new("POST", "/login").with_remote_addr(client));
    assert!(tx1.intervention().is_none());

    // T+2s: try 2 -> pass
    let mut tx2 = waf.new_transaction_at(t0 + Duration::from_secs(2));
    tx2.process_request_headers(&RequestHead::new("POST", "/login").with_remote_addr(client));
    assert!(tx2.intervention().is_none());

    // T+4s: try 3 -> 429 rate limited!
    let mut tx3 = waf.new_transaction_at(t0 + Duration::from_secs(4));
    tx3.process_request_headers(&RequestHead::new("POST", "/login").with_remote_addr(client));
    assert_eq!(tx3.intervention().map(|i| i.status), Some(429));

    // T+20s: TTL (10s since last expirevar at T+4s = T+14s) has expired -> counter resets to 1 -> pass!
    let t_after = t0 + Duration::from_secs(20);
    waf.persistent_store().purge_expired_at(t_after);
    assert_eq!(waf.persistent_store().bucket_count(), 0);

    let mut tx4 = waf.new_transaction_at(t_after);
    tx4.process_request_headers(&RequestHead::new("POST", "/login").with_remote_addr(client));
    assert!(tx4.intervention().is_none());
}

#[test]
fn prefilter_correctness_and_speedup() {
    let pattern =
        r"(?i)(?:\bunion\s+all\s+select\b|\binformation_schema\.tables\b|\bwaitfor\s+delay\b)";
    let pf = Prefilter::from_regex(pattern).expect("extracts literals for all branches");
    assert_eq!(pf.literals().len(), 3);
    assert!(!pf.might_match(b"normal clean request payload with no sql keywords"));
    assert!(pf.might_match(b"1 UNION ALL SELECT 1,2,3"));
    assert!(pf.might_match(b"select * from INFORMATION_SCHEMA.TABLES"));

    let rules =
        format!(r#"SecRule ARGS "@rx {pattern}" "id:942999,phase:2,deny,msg:'SQLi pattern'""#);
    let waf_on = Waf::from_seclang(
        WafConfig {
            regex_prefilter: true,
            ..Default::default()
        },
        &rules,
    )
    .expect("compiles");
    let waf_off = Waf::from_seclang(
        WafConfig {
            regex_prefilter: false,
            ..Default::default()
        },
        &rules,
    )
    .expect("compiles");

    let cases = [
        "/?q=hello+world",
        "/?q=1+UNION+ALL+SELECT+1,2",
        "/?q=information_schema.tables",
        "/?q=waitfor+delay+'0:0:5'",
        "/?q=just+some+text+about+unions",
    ];
    for uri in cases {
        let mut t1 = waf_on.new_transaction();
        t1.process_request_headers(&RequestHead::new("GET", uri));
        t1.process_request_body(b"");

        let mut t2 = waf_off.new_transaction();
        t2.process_request_headers(&RequestHead::new("GET", uri));
        t2.process_request_body(b"");

        assert_eq!(
            t1.intervention().is_some(),
            t2.intervention().is_some(),
            "prefilter on/off parity failed for {uri}"
        );
    }
}

#[test]
fn config_time_rule_modifications() {
    let rules = r#"
SecRule ARGS "@contains alpha" "id:10,phase:2,deny,tag:'group-a',msg:'msg-alpha'"
SecRule ARGS "@contains beta" "id:11,phase:2,deny,tag:'group-b',msg:'msg-beta'"
SecRule ARGS "@contains gamma" "id:12,phase:2,deny,tag:'group-c',msg:'msg-gamma'"
SecRule ARGS "@contains secret" "id:13,phase:2,deny,tag:'group-d',msg:'msg-secret'"
SecRule ARGS "@contains delta" "id:14,phase:2,deny,status:403,msg:'msg-delta'"

# Remove id 10 by ID, id 11 by tag, id 12 by msg
SecRuleRemoveById 10
SecRuleRemoveByTag group-b
SecRuleRemoveByMsg "msg-gamma"
# Exclude ARGS:safe from rule 13
SecRuleRemoveTargetById 13 ARGS:safe
# Update rule 14 status to 418
SecRuleUpdateActionById 14 "status:418"
"#;

    let waf = Waf::from_seclang(WafConfig::default(), rules).expect("compiles");
    assert_eq!(waf.rule_count(), 2, "rules 10, 11, 12 removed");

    // Removed rules do not trigger.
    let mut tx1 = waf.new_transaction();
    tx1.process_request_headers(&RequestHead::new("GET", "/?a=alpha&b=beta&c=gamma"));
    tx1.process_request_body(b"");
    assert!(tx1.intervention().is_none());

    // Excluded target ARGS:safe does not trigger rule 13, while ARGS:unsafe does.
    let mut tx2 = waf.new_transaction();
    tx2.process_request_headers(&RequestHead::new("GET", "/?safe=secret"));
    tx2.process_request_body(b"");
    assert!(tx2.intervention().is_none());

    let mut tx3 = waf.new_transaction();
    tx3.process_request_headers(&RequestHead::new("GET", "/?unsafe=secret"));
    tx3.process_request_body(b"");
    assert_eq!(tx3.intervention().map(|i| i.rule_id), Some(13));

    // Updated action status on rule 14.
    let mut tx4 = waf.new_transaction();
    tx4.process_request_headers(&RequestHead::new("GET", "/?x=delta"));
    tx4.process_request_body(b"");
    assert_eq!(tx4.intervention().map(|i| i.status), Some(418));
}
