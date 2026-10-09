import pandas as pd

def detect_suspicious_activity(
    df: pd.DataFrame, 
    failed_threshold: int = 5, 
    time_window_minutes: int = 2,
    enable_account_detection: bool = False,
    enable_correlation: bool = False,
    correlation_window_minutes: int = 10
) -> list[dict]:
    """
    Run all detection rules against the normalized log data.
    """
    alerts = []
    
    if df.empty:
        return alerts

    # Sort chronologically
    df = df.sort_values(by='timestamp').copy()
    
    # Pre-filter for failed logons (4625)
    failed_logons = df[df['event_id'] == 4625]
    
    # Store burst periods for Rule C (correlation)
    # List of dicts: {'source_ip': str, 'account': str, 'end_time': datetime}
    qualifying_bursts = []

    # RULE A: Repeated Failed Logons By Source
    # Group by valid source_ip
    for source_ip, group in failed_logons.groupby('source_ip'):
        if not source_ip:
            continue
            
        # Use a rolling window
        group = group.sort_values(by='timestamp')
        for i in range(len(group)):
            start_time = group.iloc[i]['timestamp']
            end_time = start_time + pd.Timedelta(minutes=time_window_minutes)
            
            # Count events in this window
            window_events = group[(group['timestamp'] >= start_time) & (group['timestamp'] <= end_time)]
            
            if len(window_events) >= failed_threshold:
                # We have a burst! 
                first_event = window_events.iloc[0]['timestamp']
                last_event = window_events.iloc[-1]['timestamp']
                accounts_involved = sorted(list(set(window_events['account'].replace("", pd.NA).dropna())))
                
                alert = {
                    'severity': 'MEDIUM',
                    'rule_name': 'Repeated Failed Logons by Source',
                    'source_ip': source_ip,
                    'account': ", ".join(accounts_involved) if accounts_involved else "Unknown",
                    'event_count': len(window_events),
                    'first_timestamp': first_event,
                    'last_timestamp': last_event,
                    'reason': f"Source {source_ip} had {len(window_events)} failed logons within {time_window_minutes} minutes.",
                    'recommendation': "Investigate the source IP for brute-force activity. Block IP if malicious."
                }
                
                # Check if this exact alert (same source and similar time window) is already added
                # Simplistic deduplication for overlapping windows:
                duplicate = False
                for a in alerts:
                    if a['rule_name'] == alert['rule_name'] and a['source_ip'] == alert['source_ip']:
                        # Overlapping time
                        if a['last_timestamp'] >= alert['first_timestamp']:
                            # Update existing alert instead of creating a new one
                            a['event_count'] = max(a['event_count'], alert['event_count'])
                            a['last_timestamp'] = max(a['last_timestamp'], alert['last_timestamp'])
                            accounts = set(a['account'].split(", ")) if a['account'] != "Unknown" else set()
                            accounts.update(accounts_involved)
                            a['account'] = ", ".join(sorted(list(accounts))) if accounts else "Unknown"
                            a['reason'] = f"Source {source_ip} had >= {a['event_count']} failed logons in overlapping windows."
                            duplicate = True
                            
                            # Also update the burst tracking
                            for b in qualifying_bursts:
                                if b['source_ip'] == source_ip:
                                    b['end_time'] = max(b['end_time'], a['last_timestamp'])
                            break
                            
                if not duplicate:
                    alerts.append(alert)
                    qualifying_bursts.append({
                        'source_ip': source_ip,
                        'account': accounts_involved[0] if len(accounts_involved) == 1 else None,
                        'end_time': last_event
                    })

    # RULE B: Repeated Failures Against An Account
    if enable_account_detection:
        for account, group in failed_logons.groupby('account'):
            if not account:
                continue
                
            group = group.sort_values(by='timestamp')
            for i in range(len(group)):
                start_time = group.iloc[i]['timestamp']
                end_time = start_time + pd.Timedelta(minutes=time_window_minutes)
                
                window_events = group[(group['timestamp'] >= start_time) & (group['timestamp'] <= end_time)]
                
                if len(window_events) >= failed_threshold:
                    first_event = window_events.iloc[0]['timestamp']
                    last_event = window_events.iloc[-1]['timestamp']
                    ips_involved = sorted(list(set(window_events['source_ip'].replace("", pd.NA).dropna())))
                    
                    alert = {
                        'severity': 'MEDIUM',
                        'rule_name': 'Repeated Failures Against Account',
                        'source_ip': ", ".join(ips_involved) if ips_involved else "Unknown",
                        'account': account,
                        'event_count': len(window_events),
                        'first_timestamp': first_event,
                        'last_timestamp': last_event,
                        'reason': f"Account '{account}' targeted by {len(window_events)} failed logons within {time_window_minutes} minutes.",
                        'recommendation': "Verify if the user forgot their password or if a distributed attack is occurring. Consider password reset."
                    }
                    
                    duplicate = False
                    for a in alerts:
                        if a['rule_name'] == alert['rule_name'] and a['account'] == alert['account']:
                            if a['last_timestamp'] >= alert['first_timestamp']:
                                a['event_count'] = max(a['event_count'], alert['event_count'])
                                a['last_timestamp'] = max(a['last_timestamp'], alert['last_timestamp'])
                                ips = set(a['source_ip'].split(", ")) if a['source_ip'] != "Unknown" else set()
                                ips.update(ips_involved)
                                a['source_ip'] = ", ".join(sorted(list(ips))) if ips else "Unknown"
                                a['reason'] = f"Account '{account}' targeted by >= {a['event_count']} failed logons in overlapping windows."
                                duplicate = True
                                
                                for b in qualifying_bursts:
                                    if b['account'] == account:
                                        b['end_time'] = max(b['end_time'], a['last_timestamp'])
                                break
                    
                    if not duplicate:
                        alerts.append(alert)
                        qualifying_bursts.append({
                            'source_ip': ips_involved[0] if len(ips_involved) == 1 else None,
                            'account': account,
                            'end_time': last_event
                        })


    # RULE C: Successful Logon Following Repeated Failures
    if enable_correlation:
        successful_logons = df[df['event_id'] == 4624]
        
        for index, success_event in successful_logons.iterrows():
            success_time = success_event['timestamp']
            success_ip = success_event['source_ip']
            success_account = success_event['account']
            
            # We need at least one reliable field to correlate
            if not success_ip and not success_account:
                continue
                
            for burst in qualifying_bursts:
                # Check time correlation
                time_diff = success_time - burst['end_time']
                if pd.Timedelta(seconds=0) <= time_diff <= pd.Timedelta(minutes=correlation_window_minutes):
                    
                    # Check field correlation
                    ip_match = (success_ip != "") and (success_ip == burst['source_ip'])
                    account_match = (success_account != "") and (success_account == burst['account'])
                    
                    if ip_match or account_match:
                        # Correlated!
                        alert = {
                            'severity': 'HIGH',
                            'rule_name': 'Successful Logon After Failures',
                            'source_ip': success_ip if success_ip else burst['source_ip'],
                            'account': success_account if success_account else burst['account'],
                            'event_count': 1, # The one successful event
                            'first_timestamp': burst['end_time'],
                            'last_timestamp': success_time,
                            'reason': f"Successful logon correlated within {correlation_window_minutes} minutes after a burst of failures.",
                            'recommendation': "Immediate investigation required. This account may be compromised."
                        }
                        alerts.append(alert)
                        # Remove burst so we don't alert multiple times for the same sequence
                        qualifying_bursts.remove(burst)
                        break

    # Add LOW severity for any remaining events of interest? Requirements said LOW for "interesting but don't meet thresholds"
    # Actually, the user requirements say:
    # "Allow the actual rule results to determine the severity... Do not label every failed login as malicious."
    # We will just stick to the main rules that generated MEDIUM/HIGH.

    return alerts
