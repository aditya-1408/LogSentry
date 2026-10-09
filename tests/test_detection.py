import pandas as pd
from logsentry.detection import detect_suspicious_activity

def create_sample_df(data: list) -> pd.DataFrame:
    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    # Add optional columns if missing
    for col in ['account', 'source_ip']:
        if col not in df.columns:
            df[col] = ""
    return df

def test_rule_a_below_threshold():
    # 4 failures within 2 minutes should NOT trigger default threshold of 5
    data = [
        {'timestamp': '2023-10-27T08:00:00', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:00:10', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:00:20', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:00:30', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
    ]
    df = create_sample_df(data)
    alerts = detect_suspicious_activity(df, failed_threshold=5, time_window_minutes=2)
    assert len(alerts) == 0

def test_rule_a_meets_threshold():
    # 5 failures within 2 minutes SHOULD trigger
    data = [
        {'timestamp': '2023-10-27T08:00:00', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:00:10', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:00:20', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:00:30', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:00:40', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
    ]
    df = create_sample_df(data)
    alerts = detect_suspicious_activity(df, failed_threshold=5, time_window_minutes=2)
    assert len(alerts) == 1
    assert alerts[0]['rule_name'] == 'Repeated Failed Logons by Source'
    assert alerts[0]['severity'] == 'MEDIUM'

def test_rule_a_outside_window():
    # 5 failures but spread outside 2 minutes should NOT trigger
    data = [
        {'timestamp': '2023-10-27T08:00:00', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:01:00', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:02:00', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:03:00', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:04:00', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
    ]
    df = create_sample_df(data)
    alerts = detect_suspicious_activity(df, failed_threshold=5, time_window_minutes=2)
    assert len(alerts) == 0

def test_rule_a_different_sources():
    # Different sources grouped separately
    data = [
        {'timestamp': '2023-10-27T08:00:00', 'event_id': 4625, 'source_ip': '1.1.1.1'},
        {'timestamp': '2023-10-27T08:00:10', 'event_id': 4625, 'source_ip': '1.1.1.1'},
        {'timestamp': '2023-10-27T08:00:20', 'event_id': 4625, 'source_ip': '1.1.1.1'},
        {'timestamp': '2023-10-27T08:00:00', 'event_id': 4625, 'source_ip': '2.2.2.2'},
        {'timestamp': '2023-10-27T08:00:10', 'event_id': 4625, 'source_ip': '2.2.2.2'},
        {'timestamp': '2023-10-27T08:00:20', 'event_id': 4625, 'source_ip': '2.2.2.2'},
    ]
    df = create_sample_df(data)
    alerts = detect_suspicious_activity(df, failed_threshold=3, time_window_minutes=2)
    assert len(alerts) == 2

def test_rule_b_account_detection():
    data = [
        {'timestamp': '2023-10-27T08:00:00', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'root'},
        {'timestamp': '2023-10-27T08:00:10', 'event_id': 4625, 'source_ip': '2.2.2.2', 'account': 'root'},
        {'timestamp': '2023-10-27T08:00:20', 'event_id': 4625, 'source_ip': '3.3.3.3', 'account': 'root'},
    ]
    df = create_sample_df(data)
    # Shouldn't trigger rule A since IPs are different
    alerts = detect_suspicious_activity(df, failed_threshold=3, time_window_minutes=2, enable_account_detection=True)
    assert len(alerts) == 1
    assert alerts[0]['rule_name'] == 'Repeated Failures Against Account'
    assert alerts[0]['account'] == 'root'

def test_rule_c_correlation():
    data = [
        {'timestamp': '2023-10-27T08:00:00', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:00:10', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:00:20', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:05:00', 'event_id': 4624, 'source_ip': '1.1.1.1', 'account': 'admin'},
    ]
    df = create_sample_df(data)
    alerts = detect_suspicious_activity(df, failed_threshold=3, time_window_minutes=2, enable_correlation=True)
    
    assert len(alerts) == 2
    rule_c_alerts = [a for a in alerts if a['rule_name'] == 'Successful Logon After Failures']
    assert len(rule_c_alerts) == 1
    assert rule_c_alerts[0]['severity'] == 'HIGH'

def test_missing_ips_no_shared_alert():
    data = [
        {'timestamp': '2023-10-27T08:00:00', 'event_id': 4625, 'source_ip': '', 'account': 'a'},
        {'timestamp': '2023-10-27T08:00:10', 'event_id': 4625, 'source_ip': '', 'account': 'b'},
        {'timestamp': '2023-10-27T08:00:20', 'event_id': 4625, 'source_ip': '', 'account': 'c'},
    ]
    df = create_sample_df(data)
    alerts = detect_suspicious_activity(df, failed_threshold=3, time_window_minutes=2)
    assert len(alerts) == 0 # Empty IPs shouldn't group together

def test_missing_correlation_fields():
    data = [
        {'timestamp': '2023-10-27T08:00:00', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:00:10', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:00:20', 'event_id': 4625, 'source_ip': '1.1.1.1', 'account': 'admin'},
        {'timestamp': '2023-10-27T08:05:00', 'event_id': 4624, 'source_ip': '', 'account': ''}, # Missing fields
    ]
    df = create_sample_df(data)
    alerts = detect_suspicious_activity(df, failed_threshold=3, time_window_minutes=2, enable_correlation=True)
    
    assert len(alerts) == 1 # Only rule A should trigger
    assert alerts[0]['rule_name'] != 'Successful Logon After Failures'
