use std::time::Duration;

/*

Select(event)
Window(WindowType(time | n, step))
Filter(preds)
Map


*/

/// Specifies the window type used to aggregate unbounded streams (i.e. eBPF
/// events) into bounded relations. Three window types are supported:
/// - Time-based windows (time interval, step)
/// - Data-based windows (size, step)
/// - Session-based windows (inactivity threshold)
pub enum WindowType {
    Time(Duration, Duration),
    Count(usize, usize),
    Session(Duration),
}
