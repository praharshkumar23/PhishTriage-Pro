from datetime import datetime

def generate_handoff(incident_id, url, users_targeted, department,
                     clicked_users, containment_status, next_action,
                     mitre_chain, assigned_to):
    clicked_list  = ", ".join(clicked_users) if clicked_users else "None"
    clicked_count = len(clicked_users)
    icon = "🔴" if containment_status == "Open" else "🟡" if containment_status == "In Progress" else "🟢"
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M IST")
    return f"""{icon} {containment_status.upper()} — {incident_id}
Generated: {ts}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
URL:         {url}
Who got it:  {users_targeted} users ({department})
Who clicked: {clicked_count} user(s) — {clicked_list}
Status:      {containment_status}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MITRE Chain: {mitre_chain}
Next action: {next_action}
Assigned to: {assigned_to}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""