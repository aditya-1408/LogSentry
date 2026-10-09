import pandas as pd
import re

# Mapping for column normalization
COLUMN_MAPPINGS = {
    "date and time": "timestamp",
    "timecreated": "timestamp",
    "event id": "event_id",
    "id": "event_id",
    "targetusername": "account",
    "account name": "account",
    "ipaddress": "source_ip",
    "source network address": "source_ip",
    "computer name": "computer",
    "machinename": "computer",
    "message": "description"
}

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize the column names of a DataFrame."""
    # Strip whitespace, lower case, and rename
    df.columns = df.columns.str.strip().str.lower()
    df.rename(columns=COLUMN_MAPPINGS, inplace=True)
    return df

def extract_ip_from_message(message: str) -> str:
    """Extract IPv4 or IPv6 address from a message string if possible."""
    if not isinstance(message, str):
        return ""
    
    # Try to find common IP patterns.
    # Note: A simplistic approach as requested for a beginner-friendly project.
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    # Simplified IPv6 matching pattern for log texts
    ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'
    
    ipv4_match = re.search(ipv4_pattern, message)
    if ipv4_match:
        return ipv4_match.group(0)
    
    ipv6_match = re.search(ipv6_pattern, message)
    if ipv6_match:
        return ipv6_match.group(0)
        
    return ""

def parse_logs(file_obj) -> pd.DataFrame:
    """Parse CSV logs from a file-like object and return a normalized DataFrame."""
    try:
        # Read CSV with string type to avoid unexpected casting
        df = pd.read_csv(file_obj, dtype=str)
    except Exception as e:
        raise ValueError(f"Failed to read CSV: {e}")
        
    if df.empty:
        raise ValueError("The uploaded CSV file is empty.")

    # Normalize columns
    df = normalize_columns(df)
    
    # Verify required columns exist
    if 'timestamp' not in df.columns or 'event_id' not in df.columns:
        raise ValueError("Missing required columns: 'timestamp' and 'event_id' are mandatory.")

    # Capture raw samples for debugging
    raw_ts_sample = df['timestamp'].dropna().head(1).tolist()
    raw_id_sample = df['event_id'].dropna().head(1).tolist()
    
    # Parse event_id to integers if possible, dropping invalid ones
    # Use regex to extract the first number in case it contains text (e.g., '4624 Logon')
    df['event_id'] = df['event_id'].astype(str).str.extract(r'(\d+)')[0]
    df['event_id'] = pd.to_numeric(df['event_id'], errors='coerce')
    
    original_len = len(df)
    
    # Drop rows where timestamp or event_id is entirely missing/invalid
    df = df.dropna(subset=['timestamp', 'event_id']).copy()
    
    # Parse timestamps
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', format='mixed')
    df = df.dropna(subset=['timestamp']).copy()
    
    if df.empty and original_len > 0:
        raise ValueError(f"All rows dropped! Raw timestamp sample: {raw_ts_sample}, Raw event_id sample: {raw_id_sample}")
    
    # Optional columns initialization
    for col in ['account', 'source_ip', 'computer', 'description']:
        if col not in df.columns:
            df[col] = ""
    
    # Ensure optional columns are treated as strings and handle missing values
    df['account'] = df['account'].fillna("").astype(str).str.strip()
    df['computer'] = df['computer'].fillna("").astype(str).str.strip()
    df['description'] = df['description'].fillna("").astype(str).str.strip()
    df['source_ip'] = df['source_ip'].fillna("").astype(str).str.strip()

    # Treat "-" or empty string as invalid IPs
    df.loc[df['source_ip'] == "-", 'source_ip'] = ""
    
    # Attempt to extract missing IPs from description
    mask_missing_ip = (df['source_ip'] == "") & (df['description'] != "")
    if mask_missing_ip.any():
        df.loc[mask_missing_ip, 'source_ip'] = df.loc[mask_missing_ip, 'description'].apply(extract_ip_from_message)

    return df
