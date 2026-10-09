def validate_dataframe(df) -> tuple[bool, str]:
    """
    Validate that the DataFrame contains the necessary structure and valid data.
    Returns (is_valid, error_message).
    """
    if df is None or df.empty:
        return False, "Data is empty or could not be loaded."
        
    required_columns = ['timestamp', 'event_id']
    for col in required_columns:
        if col not in df.columns:
            return False, f"Missing required column: '{col}'."
            
    return True, "Valid"
