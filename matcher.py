import re
import ahocorasick

class MatcherEngine:
    def __init__(self):
        self.ac_automaton = ahocorasick.Automaton()
        self.regex_rules = []
        self.literal_rules = {}
        self.built = False

    def add_literal_rule(self, rule_id, pattern, protocol, action):
        self.ac_automaton.add_word(str(rule_id), pattern) #self.ac_automaton.add_word(pattern.encode(), rule_id)
        self.literal_rules[rule_id] = {
            'pattern': pattern,
            'protocol': protocol,
            'action': action,
            'type': 'literal'
        }

    def add_regex_rule(self, rule_id, pattern, protocol, action):
        self.regex_rules.append({
            'id': rule_id,
            'regex': pattern if isinstance(pattern, bytes) else pattern.encode(),
            'protocol': protocol,
            'action': action,
            'type': 'regex'
        })

    def build(self):
        self.ac_automaton.make_automaton()
        self.built = True

    def match(self, data, protocol):
        if not self.built:
            return []

        matches = []

        if isinstance(data, str):
            data = data.encode()
        
        for rule in self.regex_rules:#[b"malware*", b"Backdoor", b"DNS*", b"DHCP*", b"attack", b"shell.php"]:
            try:
                if rule['protocol'] == 'any' or rule['protocol'] == protocol:
                    print(data)
                    match = {"rule_id":rule['id'], "matches": set(re.compile(rule['regex'], flags=re.IGNORECASE).findall(data)), "action": "drop"}
                    if len(match['matches']) > 0:
                        matches.append(match)
                        print(matches)
            except Exception as e:
                print(str(e))

        return matches[::]
