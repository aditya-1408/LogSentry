import io
import pandas as pd
import pytest
from logsentry.parser import parse_logs, extract_ip_from_message

def test_extract_ip_from_message():
    assert extract_ip_from_message("Logon failed from 192.168.1.100") == "192.168.1.100"
    assert extract_ip_from_message("No IP here") == ""
    assert extract_ip_from_message("IPv6 test 2001:0db8:85a3:0000:0000:8a2e:0370:7334 is here") == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

def test_parse_logs_valid():
    csv_data = """timestamp,event_id,account,source_ip
2023-10-27T08:00:00,4624,jdoe,192.168.1.50
2023-10-27T08:05:00,4625,asmith,192.168.1.51
"""
    df = parse_logs(io.StringIO(csv_data))
    
    assert len(df) == 2
    assert 'timestamp' in df.columns
    assert 'event_id' in df.columns
    assert 'account' in df.columns
    assert 'source_ip' in df.columns
    assert 'computer' in df.columns # Should be added even if missing in input
    assert df.iloc[0]['event_id'] == 4624
    assert df.iloc[1]['account'] == 'asmith'

def test_parse_logs_column_mapping():
    csv_data = """TimeCreated,Event ID,TargetUserName,IpAddress
2023-10-27T08:00:00,4624,jdoe,192.168.1.50
"""
    df = parse_logs(io.StringIO(csv_data))
    
    assert 'timestamp' in df.columns
    assert 'event_id' in df.columns
    assert 'account' in df.columns
    assert 'source_ip' in df.columns
    assert df.iloc[0]['account'] == 'jdoe'

def test_parse_logs_missing_optional():
    csv_data = """timestamp,event_id
2023-10-27T08:00:00,4624
"""
    df = parse_logs(io.StringIO(csv_data))
    assert len(df) == 1
    assert df.iloc[0]['account'] == ""
    assert df.iloc[0]['source_ip'] == ""

def test_parse_logs_invalid_timestamp():
    csv_data = """timestamp,event_id
invalid_date,4624
2023-10-27T08:00:00,4625
"""
    df = parse_logs(io.StringIO(csv_data))
    assert len(df) == 1 # The row with invalid date should be dropped
    assert df.iloc[0]['event_id'] == 4625

def test_parse_logs_invalid_event_id():
    csv_data = """timestamp,event_id
2023-10-27T08:00:00,not_a_number
2023-10-27T08:00:00,4625
"""
    df = parse_logs(io.StringIO(csv_data))
    assert len(df) == 1
    assert df.iloc[0]['event_id'] == 4625

def test_parse_logs_empty():
    with pytest.raises(ValueError, match="The uploaded CSV file is empty."):
        parse_logs(io.StringIO(""))

def test_parse_logs_missing_required():
    csv_data = """account,source_ip
jdoe,192.168.1.50
"""
    with pytest.raises(ValueError, match="Missing required columns"):
        parse_logs(io.StringIO(csv_data))
