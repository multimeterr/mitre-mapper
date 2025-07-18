import pandas as pd
from rapidfuzz import process, fuzz
from pyattck import Attck

attack = Attck()

def get_attack_id(tech):
    for ref in tech.external_references:
        if hasattr(ref, 'source_name') and ref.source_name == 'mitre-attack':
            return ref.external_id
    return 'N/A'


techniques = []
for tech in attack.enterprise.techniques:
    techniques.append({
        'id': get_attack_id(tech),
        'name': tech.name,
        'description': getattr(tech, 'description', '') or '',
        'tactics': [t.name for t in tech.tactics]
    })

log_df = pd.read_csv('event_logs.csv', names=['event_description'], header=None)

mapped_rows = []
for event in log_df['event_description']:
    best_match = None
    best_score = 0
    for tech in techniques:
        match_score = process.extractOne(
            event,
            [tech['name'], tech['description']],
            scorer=fuzz.token_sort_ratio
        )
        score = match_score[1] if match_score else 0
        if score > best_score:
            best_score = score
            best_match = tech

    tactic_names = ', '.join(best_match['tactics']) if best_match and best_match['tactics'] else 'N/A'
    mapped_rows.append({
        'Event': event,
        'Tactic': tactic_names,
        'Technique Name': best_match['name'] if best_match else 'N/A',
        'Technique ID': best_match['id'] if best_match else 'N/A',
        'Confidence': f"{best_score:.1f}%"
    })

output_df = pd.DataFrame(mapped_rows)
output_df.to_excel('output_mapped.xlsx', index=False)
print("Mapping completed! exported to: 'output_mapped.xlsx'")
