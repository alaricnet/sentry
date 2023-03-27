use std::env;
use prettytable::{Table, Row, Cell};
use prettytable::{row, cell};


use reqwest::blocking::Client;
use serde_json::Value;
use whois_rust::{WhoIs, WhoIsLookupOptions};
use reqwest::header::{HeaderMap, CONTENT_TYPE};



const OPENPHISH_API_URL: &str = "https://openphish.com/feed.txt";
const URLHAUS_API_URL: &str = "https://urlhaus-api.abuse.ch/v1/url/";

// A CLI that checks the input URL for domain information, phishing links and Malicious URLs
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <url>", args[0]);
        return;
    }

    let url = &args[1];
    let openphish_result = check_openphish(url);
    let urlhaus_result = check_urlhaus(url);

    let mut table = Table::new();
    table.add_row(Row::new(vec![Cell::new("Check").style_spec("bFg"), Cell::new("Result").style_spec("bFg")]));
    table.add_row(row![ "OpenPhish", if openphish_result { "✓" } else { "✗" } ]);
    table.add_row(row![ "URLhaus", if urlhaus_result { "✓" } else { "✗" } ]);

    table.print_tty(true);

    if let Some(registration_info) = get_domain_registration_info(url) {
        println!("\nDomain registration info:\n{}", registration_info);
    }
}



fn check_openphish(url: &str) -> bool {
    let client = Client::new();

    let response = client.get(OPENPHISH_API_URL)
        .send()
        .expect("Failed to send request to OpenPhish");

    let text = response.text().expect("Failed to parse OpenPhish response");

    for line in text.lines() {
        if line == url {
            return false;
        }
    }

    true
}


fn check_urlhaus(url: &str) -> bool {
    let client = Client::new();
    let params = format!("url={}", url);

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/x-www-form-urlencoded".parse().unwrap());

    let response = client.post(URLHAUS_API_URL)
        .headers(headers)
        .body(params)
        .send()
        .expect("Failed to send request to URLhaus");

    let response_text = response.text().expect("Failed to read URLhaus response");
    

    let json: Value = serde_json::from_str(&response_text).expect("Failed to parse URLhaus response");

    if let Some(query_status) = json.get("query_status") {
        return query_status.as_str().unwrap_or("") != "malicious";
    }

    true
}

fn get_domain_registration_info(domain: &str) -> Option<String> {
    let servers_json = include_str!("servers.json");
    let whois = WhoIs::from_string(servers_json).unwrap();

    let lookup_options = WhoIsLookupOptions::from_string(domain).unwrap();
    let result = whois.lookup(lookup_options);

    match result {
        Ok(info) => Some(info),
        Err(e) => {
            eprintln!("Failed to get registration info for {}: {}", domain, e);
            None
        }
    }
}
