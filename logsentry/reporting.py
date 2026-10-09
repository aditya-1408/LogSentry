import pandas as pd
import io

def sanitize_for_csv(value) -> str:
    """
    Escape spreadsheet-formula prefixes (=, +, -, @) in user-controlled text 
    to prevent CSV injection attacks.
    """
    if pd.isna(value):
        return ""
        
    val_str = str(value)
    if val_str.startswith(('=', '+', '-', '@')):
        return f"'{val_str}"
    return val_str

def generate_alerts_csv(alerts: list[dict]) -> str:
    """
    Generate a CSV string from the list of alerts, sanitizing user inputs.
    """
    if not alerts:
        # Return empty CSV with headers
        headers = ["severity", "rule_name", "source_ip", "account", "event_count", "first_timestamp", "last_timestamp", "reason", "recommendation"]
        return ",".join(headers) + "\n"
        
    df = pd.DataFrame(alerts)
    
    # Sanitize potentially user-controlled fields
    # Account names and reason strings (which contain account/ip) might be user-controlled
    for col in ['account', 'source_ip', 'reason']:
        if col in df.columns:
            df[col] = df[col].apply(sanitize_for_csv)
            
    # Write to string buffer
    buffer = io.StringIO()
    df.to_csv(buffer, index=False)
    return buffer.getvalue()

def generate_events_csv(df: pd.DataFrame) -> str:
    """
    Generate a CSV string from the filtered events DataFrame, sanitizing user inputs.
    """
    if df.empty:
        return ""
        
    # Create a copy to avoid modifying the original dataframe
    export_df = df.copy()
    
    # Sanitize user-controlled fields
    for col in ['account', 'source_ip', 'computer', 'description']:
        if col in export_df.columns:
            export_df[col] = export_df[col].apply(sanitize_for_csv)
            
    buffer = io.StringIO()
    export_df.to_csv(buffer, index=False)
    return buffer.getvalue()
