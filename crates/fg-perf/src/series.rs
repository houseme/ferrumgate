//! Chart output (WP-69 §3.2): one series per metric and window with the
//! per-period peak line. Missing data renders as `null` so the interface
//! shows "no data" instead of a wrong value; points carry UTC RFC 3339
//! timestamps (conventions §3.5).

use std::time::SystemTime;

use serde::{Serialize, ser::SerializeStruct as _};

use crate::history::{
    ExtraMetric, History, agg_for, extra_agg_for, extra_sample_value, sample_value,
};
use crate::model::{Metric, Window, limits};

/// One chart point; `value` is `None` when the metric had no data.
#[derive(Clone, Debug, PartialEq)]
pub struct Point {
    pub at: SystemTime,
    pub value: Option<f64>,
}

impl Serialize for Point {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Point", 2)?;
        state.serialize_field("at", &crate::rfc3339(self.at))?;
        state.serialize_field("value", &self.value)?;
        state.end()
    }
}

/// The chart payload for one metric: the range tag, the step in seconds,
/// the points and the per-period peak (equal to the value on the 60 s
/// tier where every point is one sample).
#[derive(Clone, Debug, Serialize)]
pub struct Series {
    pub range: &'static str,
    pub step: u32,
    pub points: Vec<Point>,
    pub peak: Vec<Option<f64>>,
}

/// Builds the series for one metric and window from the history rings.
pub(crate) fn build(history: &History, metric: Metric, window: Window) -> Series {
    build_with(
        history,
        window,
        |sample| sample_value(sample, metric),
        |bucket| agg_for(&bucket.agg, metric),
    )
}

/// Builds the series for an extra overview metric (load, net, managed totals).
pub(crate) fn build_extra(history: &History, metric: ExtraMetric, window: Window) -> Series {
    build_with(
        history,
        window,
        |sample| extra_sample_value(sample, metric),
        |bucket| extra_agg_for(&bucket.agg, metric),
    )
}

fn build_with(
    history: &History,
    window: Window,
    read_sample: impl Fn(&crate::history::Sample) -> Option<f64>,
    read_bucket: impl Fn(&crate::history::Bucket) -> &crate::history::Agg,
) -> Series {
    match window {
        Window::Min => {
            let points: Vec<Point> = history
                .short()
                .iter()
                .map(|sample| Point {
                    at: sample.at,
                    value: read_sample(sample),
                })
                .collect();
            let peak = points.iter().map(|point| point.value).collect();
            Series {
                range: window.range(),
                step: limits::SAMPLE_INTERVAL.as_secs() as u32,
                points,
                peak,
            }
        }
        Window::Hour | Window::Day => {
            let buckets = match window {
                Window::Hour => history.hour(),
                _ => history.day(),
            };
            let mut points = Vec::with_capacity(buckets.len());
            let mut peak = Vec::with_capacity(buckets.len());
            for bucket in buckets {
                let agg = read_bucket(bucket);
                points.push(Point {
                    at: bucket_at(bucket.key, window),
                    value: agg.mean(),
                });
                peak.push(agg.peak());
            }
            Series {
                range: window.range(),
                step: window.step(),
                points,
                peak,
            }
        }
    }
}

/// The wall-clock start of a bucket: minute keys for the 1-hour tier and
/// 5-minute keys for the 24-hour tier.
fn bucket_at(key: i64, window: Window) -> SystemTime {
    let secs = match window {
        Window::Day => key * 300,
        _ => key * 60,
    };
    if secs <= 0 {
        return SystemTime::UNIX_EPOCH;
    }
    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64)
}
