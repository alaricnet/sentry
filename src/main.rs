use std::env;
use reqwest::blocking::Client;
use serde_json::Value;
use serde_json::json;

const OPENPHISH_API_URL: &str = "https://openphish.com/feed.txt";

const URLHAUS_API_URL: &str = "https://urlhaus-api.abuse.ch/v1/url/";

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <url>", args[0]);
        return;
    }

    let url = &args[1];
    let openphish_result = check_openphish(url);
    let urlhaus_result = check_urlhaus(url);

    if openphish_result && urlhaus_result {
        println!("\x1b[32mSuccess: URL is safe\x1b[0m");
    } else {
        println!("\x1b[31mWarning: URL is not safe\x1b[0m");
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
    let params = json!({
        "url": url
    });

    let response = client.post(URLHAUS_API_URL)
        .json(&params)
        .send();

    match response {
        Ok(res) => {
            match res.json::<Value>() {
                Ok(json) => {
                    if let Some(query_status) = json.get("query_status") {
                        return query_status.as_str().unwrap_or("") != "malicious";
                    }
                }
                Err(_) => {
                    eprintln!("Failed to parse URLhaus response. The response might not be in the expected JSON format.");
                }
            }
        }
        Err(_) => {
            eprintln!("Failed to send request to URLhaus.");
        }
    }

    true
}

