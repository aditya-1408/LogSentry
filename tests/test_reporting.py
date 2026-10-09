import pandas as pd
from logsentry.reporting import sanitize_for_csv, generate_alerts_csv, generate_events_csv

def test_sanitize_for_csv():
    assert sanitize_for_csv("normal_string") == "normal_string"
    assert sanitize_for_csv("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert sanitize_for_csv("+1+2") == "'+1+2"
    assert sanitize_for_csv("-100") == "'-100"
    assert sanitize_for_csv("@SUM(A1:A2)") == "'@SUM(A1:A2)"
    assert sanitize_for_csv(None) == "" # Handled by pd.isna
    assert sanitize_for_csv(123) == "123"

def test_generate_alerts_csv_empty():
    csv_out = generate_alerts_csv([])
    assert "severity,rule_name,source_ip,account" in csv_out

def test_generate_alerts_csv():
    alerts = [
        {
            'severity': 'MEDIUM',
            'rule_name': 'Test Rule',
            'source_ip': '1.1.1.1',
            'account': '=malicious_account',
            'event_count': 5,
            'first_timestamp': '2023-10-27T08:00:00',
            'last_timestamp': '2023-10-27T08:05:00',
            'reason': 'Because',
            'recommendation': 'None'
        }
    ]
    
    csv_out = generate_alerts_csv(alerts)
    assert "'=malicious_account" in csv_out
    assert "MEDIUM" in csv_out
    assert "Test Rule" in csv_out

def test_generate_events_csv():
    df = pd.DataFrame([
        {'timestamp': '2023-10-27', 'event_id': 4625, 'account': '@evil', 'source_ip': '1.1.1.1', 'computer': 'A', 'description': 'B'}
    ])
    
    csv_out = generate_events_csv(df)
    assert "'@evil" in csv_out
    assert "4625" in csv_out
