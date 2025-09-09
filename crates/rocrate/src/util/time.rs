use chrono::DateTime;
use chrono::Utc;

pub fn iso8601(st: &std::time::SystemTime) -> String {
    let dt: DateTime<Utc> = (*st).into();
    format!("{}", dt.format("%+"))
}
